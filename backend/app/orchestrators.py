from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from app.osint_normalization import adaptar, normalizar_ip, parsear_servicio
from app.scan_scope import scope_allows_ip, scope_allows_domain
from app.spiderfoot_passive import (
    COMMONCRAWL_DISABLED_REASON,
    MODULES as BAXTER_SPIDERFOOT_MODULES,
    reports as passive_reports,
    selected_modules,
    unavailable_report_event,
)
from app.settings import DEFAULT_SPIDERFOOT_MODULES
from app.web_posture import inspect_host

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class OrchestratorSettings:
    web_enabled: bool = True
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "certspotter,hackertarget,rapiddns,urlscan"
    spiderfoot_url: str = "http://127.0.0.1:5001"
    spiderfoot_modules: str = DEFAULT_SPIDERFOOT_MODULES
    request_timeout_seconds: float = 30
    process_timeout_seconds: float = 900
    spiderfoot_timeout_seconds: float = 1800
    spiderfoot_poll_seconds: float = 3
    crtsh_retries: int = 2
    crtsh_timeout_seconds: float = 15
    crtsh_total_timeout_seconds: float = 45
    crtsh_enabled: bool = True


Runner = Callable[[str], Awaitable[Any]]
OnResult = Callable[[str, dict[str, Any]], Awaitable[None]]

# Se puede sustituir en pruebas para no esperar de verdad entre reintentos.
_sleep = asyncio.sleep
_REINTENTABLES = {429, 500, 502, 503, 504}
# theHarvester no informa cuándo se reinicia la cuota. Tras quota-exhausted se
# espera conservadoramente 24 h desde la respuesta; no sobrevive a reinicios.
_HARVESTER_QUOTA_COOLDOWN_SECONDS = 24 * 60 * 60
_harvester_quota_until: dict[str, float] = {}


@dataclass(frozen=True)
class RunnerOutput:
    """Resultado de un runner que, además de los datos, sabe qué IPs son del objetivo."""

    data: Any
    ips_en_alcance: tuple[str, ...] = field(default_factory=tuple)
    error: str | None = None
    failed: bool = False


def _error_message(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code} from {error.request.url.host}"
    if isinstance(error, httpx.RequestError):
        return f"{error.__class__.__name__} while contacting {error.request.url.host}"
    if isinstance(error, TimeoutError) and not str(error).strip():
        return "Excedió el tiempo máximo de ejecución"
    message = str(error).strip() or error.__class__.__name__
    return f"{error.__class__.__name__}: {message}"[:1000]


def _merge_source_data(name: str, outputs: list[Any]) -> Any:
    """Conserva el formato que espera el normalizador para una fuente."""
    if len(outputs) == 1:
        return outputs[0]
    if name == "crt.sh" and all(isinstance(output, dict) and output.get("version") == 1 for output in outputs):
        return {
            "version": 1,
            "entries": [entry for output in outputs for entry in output["entries"]],
            "queries": [query for output in outputs for query in output["queries"]],
            "covered_targets": list(dict.fromkeys(
                target for output in outputs for target in output.get("covered_targets", [])
            )),
        }
    if name == "theHarvester":
        fields = ("hosts", "vhosts", "ips", "emails", "asns")
        if not all(isinstance(output, dict) for output in outputs):
            raise ValueError("theHarvester devolvió un formato inesperado")
        return {
            **{field: [item for output in outputs for item in (output.get(field) or [])] for field in fields},
            "items": _unique_harvester_items([item for output in outputs for item in (output.get("items") or [])]),
            "runs": [run for output in outputs for run in (output.get("runs") or [])],
        }
    if not all(isinstance(output, list) for output in outputs):
        raise ValueError(f"{name} devolvió un formato inesperado")
    return [item for output in outputs for item in output]


def _unique_harvester_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (str(item.get("type", "")).lower(), str(item.get("value", "")).lower())
        if key not in unique:
            unique[key] = {**item, "sources": [], "targets": []}
        for field in ("sources", "targets"):
            unique[key][field] = list(dict.fromkeys([*unique[key][field], *(item.get(field) or [])]))
    return list(unique.values())


def _merge_outcomes(name: str, previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    contents = [item["contenido"] for item in (previous, current)
                if item.get("contenido") is not None and (name in {"crt.sh", "theHarvester", "SpiderFoot"} or item["estado"] == "completado")]
    errors = [item["error"] for item in (previous, current) if item.get("error")]
    return {
        "consultas": [q for item in (previous, current) for q in item.get("consultas", [])],
        "estado": "completado" if any(item["estado"] == "completado" for item in (previous, current)) else "fallido",
        "contenido": _merge_source_data(name, contents) if contents else None,
        "error": ("; ".join(errors))[:1000] if errors else None,
        "ips_en_alcance": list(dict.fromkeys([
            *(previous.get("ips_en_alcance") or []), *(current.get("ips_en_alcance") or []),
        ])),
    }


def _new_targets(outcomes: dict[str, dict[str, Any]], domain: str, known: set[str], ip_scope: str | None) -> list[str]:
    discovered: set[str] = set()
    for name, outcome in outcomes.items():
        if outcome["estado"] != "completado" or outcome["contenido"] is None:
            continue
        try:
            normalized = adaptar(name, outcome["contenido"], domain, outcome.get("ips_en_alcance"))
        except (TypeError, ValueError):
            logger.warning("No se pudieron extraer subdominios de %s para ampliar el escaneo", name)
            continue
        for item in normalized["observaciones"]:
            value = item["valor"]
            if item["tipo"] == "subdominio" and value not in known:
                discovered.add(value)
            elif ip_scope and item["tipo"] in {"ip", "servicio"}:
                address = value if item["tipo"] == "ip" else (parsear_servicio(value) or {}).get("ip")
                if address and ipaddress.ip_address(address).is_global and scope_allows_ip(ip_scope, address) and address not in known:
                    discovered.add(address)
    return sorted(discovered)


def _crtsh_covers_subdomains(outcome: dict[str, Any] | None, domain: str) -> bool:
    content = (outcome or {}).get("contenido")
    return bool(
        isinstance(content, dict) and content.get("version") == 1
        and any(query.get("query") == f"%.{domain}" and query.get("status") == "ok"
                for query in content.get("queries", []))
    )


async def run_all(
    domain: str,
    settings: OrchestratorSettings,
    runners: dict[str, Runner] | None = None,
    on_result: OnResult | None = None,
    timeout_seconds: float | None = None,
    targets: list[str] | None = None,
    max_targets: int | None = None,
    target_only: bool = False,
    ip_scope: str | None = None,
    excluded_targets: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Ejecuta todas las fuentes en paralelo y conserva el resultado de cada una.

    * Una fuente que falla nunca cancela a las demás.
    * `on_result(nombre, resultado)` se llama apenas termina CADA fuente, para
      guardar sus datos sin esperar a la más lenta.
    * `timeout_seconds` limita cuánto puede tardar cada fuente; al agotarse se
      marca como fallida.
    """
    exhausted_sources: set[str] = set()

    async def harvester_runner(target: str) -> RunnerOutput:
        configured = [source.strip() for source in settings.theharvester_sources.split(",") if source.strip()]
        now = time.monotonic()
        available = [source for source in configured if source.lower() not in exhausted_sources
                     and _harvester_quota_until.get(source.lower(), 0) <= now]
        skipped = [source for source in configured if source not in available]
        if not available:
            return RunnerOutput({"items": [], "runs": [{"target": target, "source_executions": [
                {"source": source, "status": "skipped", "stop_reason": "quota-exhausted", "result_count": 0}
                for source in skipped
            ]}]}, error="Proveedores omitidos por cuota agotada", failed=True)
        output = await run_theharvester(target, replace(settings, theharvester_sources=",".join(available)))
        if not isinstance(output, RunnerOutput):
            output = RunnerOutput(output)
        data = output.data
        if isinstance(data, dict):
            if skipped and not data.get("runs"):
                data["runs"] = [{"target": target, "source_executions": []}]
            for run in data.get("runs", []):
                executions = run.get("source_executions", [])
                for execution in executions:
                    if isinstance(execution, dict) and (
                        execution.get("status") == "rate-limited"
                        or execution.get("stop_reason") == "quota-exhausted"
                    ):
                        source = str(execution.get("source", "")).lower()
                        exhausted_sources.add(source)
                        if source == "hackertarget" and execution.get("stop_reason") == "quota-exhausted":
                            _harvester_quota_until[source] = time.monotonic() + _HARVESTER_QUOTA_COOLDOWN_SECONDS
                executions.extend({"source": source, "status": "skipped", "stop_reason": "quota-exhausted", "result_count": 0}
                                  for source in skipped)
        error = output.error
        if skipped:
            error = "; ".join(filter(None, [error, "Proveedores omitidos por cuota agotada: " + ", ".join(skipped)]))
        return RunnerOutput(data, output.ips_en_alcance, error=error, failed=output.failed)

    default_runners = {
        "theHarvester": harvester_runner,
        "SpiderFoot": lambda target: run_spiderfoot(target, settings),
    }
    if settings.web_enabled:
        default_runners["Web"] = lambda target: run_web(target, settings)
    if settings.crtsh_enabled:
        default_runners = {
            "crt.sh": lambda target: run_crtsh(target, settings, include_subdomains=target == domain),
            **default_runners,
        }
    selected_runners = runners if runners is not None else default_runners

    excluded_targets = dict(excluded_targets or {})
    selected_targets = [
        target for target in dict.fromkeys([*([] if target_only else [domain]), *(targets or [])])
        if target not in excluded_targets
    ]
    if ip_scope is not None:
        selected_targets = [target for target in selected_targets if (
            scope_allows_ip(ip_scope, target) and ipaddress.ip_address(target).is_global
            if normalizar_ip(target) else scope_allows_domain(ip_scope, target)
        )]

    if max_targets is not None:
        queued = selected_targets[max_targets:]
        selected_targets = selected_targets[:max_targets]
        known = set(selected_targets)
        deadline = asyncio.get_running_loop().time() + timeout_seconds if timeout_seconds else None
        expanded: set[str] = set()
        outcomes = await run_all(
            domain, settings, selected_runners, on_result=on_result,
            timeout_seconds=timeout_seconds,
            targets=selected_targets,
        )
        while len(known) < max_targets:
            new_targets = list(dict.fromkeys([*queued, *_new_targets(outcomes, domain, known, ip_scope)]))[:max_targets - len(known)]
            queued = [target for target in queued if target not in new_targets]
            if not new_targets:
                break
            remaining = deadline - asyncio.get_running_loop().time() if deadline else None
            if remaining is not None and remaining <= 0:
                queued.extend(new_targets)
                break
            known.update(new_targets)
            covered = _crtsh_covers_subdomains(outcomes.get("crt.sh"), domain)
            additional_runners = {
                name: runner for name, runner in selected_runners.items()
                if not (name == "crt.sh" and covered)
            }
            additional = await run_all(
                domain, settings,
                additional_runners,
                timeout_seconds=remaining, targets=new_targets, target_only=True,
            )
            if covered:
                content = outcomes["crt.sh"]["contenido"]
                content["covered_targets"] = list(dict.fromkeys([
                    *content.get("covered_targets", []),
                    *(target for target in new_targets if normalizar_ip(target) is None),
                ]))
                outcomes["crt.sh"].setdefault("consultas", []).extend(
                    {"objetivo": target, "estado": "completado", "metodo": "consulta de sufijo CT", "error": None}
                    for target in new_targets if normalizar_ip(target) is None
                )
                expanded.add("crt.sh")
            for name, outcome in additional.items():
                outcomes[name] = _merge_outcomes(name, outcomes[name], outcome)
                expanded.add(name)
        pending = list(dict.fromkeys([
            *queued, *_new_targets(outcomes, domain, known, ip_scope), *excluded_targets,
        ]))
        for outcome in outcomes.values():
            outcome["objetivos_pendientes"] = pending
            outcome["objetivos_omitidos"] = excluded_targets
        if on_result is not None:
            for name, outcome in outcomes.items():
                if name not in expanded:
                    continue
                try:
                    await on_result(name, outcome)
                except Exception:
                    logger.exception("No se pudo procesar el resultado de %s", name)
        return outcomes

    async def run_one(name: str, runner: Runner) -> tuple[str, dict[str, Any]]:
        domain_targets = [target for target in selected_targets if normalizar_ip(target) is None]
        if name in {"crt.sh", "theHarvester", "Web"}:
            source_targets = domain_targets
        else:
            source_targets = selected_targets
        queries: list[dict[str, Any]] = []
        outputs: list[Any] = []
        successes: list[bool] = []
        ips: list[str] = []
        errors: list[str] = []
        deadline = asyncio.get_running_loop().time() + timeout_seconds if timeout_seconds else None
        try:
            for target in source_targets:
                try:
                    remaining = deadline - asyncio.get_running_loop().time() if deadline else None
                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("Se agotó el tiempo de esta fuente")
                    output = await asyncio.wait_for(runner(target), timeout=remaining) if remaining else await runner(target)
                    if isinstance(output, RunnerOutput):
                        outputs.append(output.data)
                        successes.append(not output.failed)
                        ips.extend(output.ips_en_alcance)
                        if output.error:
                            errors.append(f"{target}: {output.error}")
                    else:
                        outputs.append(output)
                        successes.append(True)
                    queries.append({"objetivo": target, "estado": "fallido" if isinstance(output, RunnerOutput) and output.failed else "parcial" if isinstance(output, RunnerOutput) and output.error else "completado", "metodo": "validación técnica 80/443" if name == "Web" else "consulta de fuente", "error": output.error if isinstance(output, RunnerOutput) else None})
                    if (name == "crt.sh" and target == domain and isinstance(outputs[-1], dict)
                            and outputs[-1].get("version") == 1):
                        suffix_ok = any(
                            q.get("query") == f"%.{domain}" and q.get("status") == "ok"
                            for q in outputs[-1].get("queries", [])
                        )
                        # La consulta wildcard es la única necesaria para cubrir los
                        # subdominios. Si falla por cuota/proveedor, repetir cada nombre
                        # amplifica el 429/5xx y no mejora la evidencia.
                        if suffix_ok:
                            outputs[-1]["covered_targets"] = list(source_targets)
                        suffix_error = next((
                            q.get("error") for q in outputs[-1].get("queries", [])
                            if q.get("query") == f"%.{domain}" and q.get("status") == "error"
                        ), None)
                        queries.extend({
                            "objetivo": value,
                            "estado": "completado" if suffix_ok else "fallido",
                            "metodo": "consulta de sufijo CT",
                            "error": None if suffix_ok else (
                                "No evaluado: falló la consulta wildcard de crt.sh"
                                + (f" ({suffix_error})" if suffix_error else "")
                            ),
                        } for value in source_targets if value != target)
                        break
                except Exception as error:
                    queries.append({"objetivo": target, "estado": "fallido", "metodo": "consulta de fuente", "error": _error_message(error)})
                    errors.append(f"{target}: {_error_message(error)}")
            data = _merge_source_data(name, outputs) if outputs else None
            outcome = {
                "estado": "completado" if any(successes) else "fallido",
                "contenido": data,
                "error": ("; ".join(errors))[:1000] if errors else None,
                "ips_en_alcance": list(dict.fromkeys(ips)),
            }
        except Exception as error:
            outcome = {"estado": "fallido", "contenido": None, "error": _error_message(error), "ips_en_alcance": []}
        outcome["consultas"] = queries
        if on_result is not None:
            try:
                await on_result(name, outcome)
            except Exception:
                logger.exception("No se pudo procesar el resultado de %s", name)
        return name, outcome

    outcomes = await asyncio.gather(
        *(run_one(name, runner) for name, runner in selected_runners.items())
    )
    return dict(outcomes)


async def _crtsh_query(
    client: httpx.AsyncClient, query: str, settings: OrchestratorSettings, deadline: float,
) -> list[dict[str, Any]]:
    """Una búsqueda CT. Una respuesta vacía solo cuenta si llegó JSON válido."""
    intentos = min(2, max(1, settings.crtsh_retries))
    for intento in range(1, intentos + 1):
        try:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("crt.sh agotó su presupuesto global de tiempo")
            request_timeout = min(15.0, max(0.25, settings.crtsh_timeout_seconds), remaining)
            response = await client.get(
                "https://crt.sh/", params={"q": query, "output": "json"},
                headers={"Accept": "application/json"},
                timeout=httpx.Timeout(request_timeout, connect=min(5, request_timeout)),
            )
            if response.status_code in _REINTENTABLES and intento < intentos:
                retry_after = response.headers.get("Retry-After") if response.status_code == 429 else None
                delay = 5 if response.status_code == 429 and not retry_after else min(2**intento, 3)
                if retry_after:
                    try:
                        delay = max(float(retry_after), delay)
                    except ValueError:
                        pass
                remaining = deadline - asyncio.get_running_loop().time()
                if 0 <= delay < remaining:
                    logger.warning("crt.sh respondió HTTP %s; reintento %s/%s en %s s", response.status_code, intento, intentos, delay)
                    await _sleep(delay)
                    continue
            response.raise_for_status()
            if not response.text.strip():
                raise ValueError("crt.sh respondió sin cuerpo JSON")
            payload = response.json()
            if not isinstance(payload, list) or any(not isinstance(entry, dict) for entry in payload):
                raise ValueError("crt.sh devolvió un formato distinto de una lista JSON de certificados")
            return payload
        except (httpx.TimeoutException, httpx.TransportError):
            if intento == intentos:
                raise
            delay = min(2**intento, 3)
            if delay >= deadline - asyncio.get_running_loop().time():
                raise
            await _sleep(delay)
    raise RuntimeError("crt.sh agotó los reintentos")


async def run_crtsh(
    domain: str, settings: OrchestratorSettings, *, include_subdomains: bool = True,
) -> RunnerOutput:
    """Consulta el nombre exacto y, en la raíz, también todos sus subdominios."""
    # El nombre exacto se consulta primero: si la búsqueda wildcard recibe
    # 429/5xx, los certificados ya obtenidos siguen disponibles.
    queries = [domain, f"%.{domain}"] if include_subdomains else [domain]
    report: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    deadline = asyncio.get_running_loop().time() + max(1, settings.crtsh_total_timeout_seconds)
    default_timeout = max(0.25, min(15, settings.crtsh_timeout_seconds))
    timeout = httpx.Timeout(default_timeout, connect=min(5, default_timeout))
    async with httpx.AsyncClient(timeout=timeout) as client:
        for query in queries:
            checked_at = datetime.now(timezone.utc).isoformat()
            try:
                found = await _crtsh_query(client, query, settings, deadline)
                entries.extend(found)
                report.append({"query": query, "status": "ok", "entries": len(found), "checked_at": checked_at})
            except (httpx.HTTPError, ValueError, TimeoutError) as error:
                reason = _error_message(error)
                errors.append(f"{query}: {reason}")
                report.append({"query": query, "status": "error", "entries": 0,
                               "error": reason, "checked_at": checked_at})
    return RunnerOutput(
        {"version": 1, "entries": entries, "queries": report,
         "covered_targets": [domain] if any(item["status"] == "ok" for item in report) else []},
        error="; ".join(errors)[:1000] if errors else None,
        failed=not any(item["status"] == "ok" for item in report),
    )


async def run_web(domain: str, settings: OrchestratorSettings) -> RunnerOutput:
    events, errors = await inspect_host(domain, timeout=min(settings.request_timeout_seconds, 10))
    return RunnerOutput(events, error="; ".join(errors) if errors else None, failed=bool(errors and not events))


async def run_theharvester(domain: str, settings: OrchestratorSettings) -> Any:
    executable = shutil.which(settings.theharvester_bin)
    if executable is None:
        raise RuntimeError(
            "theHarvester no está disponible en este servidor. Instálalo y configura "
            "THEHARVESTER_BIN con un ejecutable local o uno disponible en PATH"
        )

    with tempfile.TemporaryDirectory(prefix="baxtersec-theharvester-") as workdir:
        report_base = Path(workdir) / "reporte"
        process = await asyncio.create_subprocess_exec(
            executable,
            "-d",
            domain,
            "-b",
            settings.theharvester_sources,
            "-f",
            str(report_base),
            cwd=workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=settings.process_timeout_seconds
            )
        except TimeoutError:
            process.kill()
            await process.communicate()
            raise TimeoutError("theHarvester excedió el tiempo máximo de ejecución")
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
                await process.communicate()
            raise

        json_report = report_base.with_suffix(".json")
        jsonl_report = report_base.with_suffix(".jsonl")
        if jsonl_report.is_file():
            payload = _read_theharvester_jsonl(jsonl_report)
            warning = _check_theharvester_source_status(jsonl_report)
            executions = payload["runs"][0]["source_executions"]
            failed = not any(source.get("status") == "completed" for source in executions) and not payload["items"]
            if not executions:
                warning = warning or "theHarvester no ejecutó ningún proveedor"
            if process.returncode:
                warning = warning or _process_error("theHarvester", stderr, stdout)
            return RunnerOutput(payload, error=warning, failed=failed)
        if process.returncode:
            raise RuntimeError(_process_error("theHarvester", stderr, stdout))
        if json_report.is_file():
            return json.loads(json_report.read_text(encoding="utf-8"))
        raise RuntimeError("theHarvester terminó sin generar el reporte JSON esperado")


def _process_error(tool: str, stderr: bytes, stdout: bytes) -> str:
    detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
    return f"{tool} terminó con error" + (f": {detail[-800:]}" if detail else "")


def _read_theharvester_jsonl(report: Path) -> dict[str, Any]:
    result: dict[str, list[str]] = {"hosts": [], "ips": [], "emails": [], "asns": []}
    field_by_type = {
        "hostname": "hosts",
        "host": "hosts",
        "ip": "ips",
        "email": "emails",
        "asn": "asns",
    }
    items: list[dict[str, Any]] = []
    summary: dict[str, Any] | None = None
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            continue
        if item.get("type") == "summary":
            summary = item
            continue
        field = field_by_type.get(str(item.get("type", "")).lower())
        value = item.get("value")
        if isinstance(value, str) and isinstance(item.get("type"), str):
            if field:
                result[field].append(value)
            items.append({"type": item["type"], "value": value, "sources": item.get("sources") or []})
    if summary is None or not isinstance(summary.get("source_executions"), list):
        raise ValueError("theHarvester no generó un resumen JSONL válido")
    for item in items:
        item["targets"] = [summary.get("target")] if summary.get("target") else []
    return {**result, "items": items, "runs": [{
        "target": summary.get("target"),
        "started_at": summary.get("started_at"),
        "completed_at": summary.get("completed_at"),
        "evidence_status": summary.get("evidence_status"),
        "source_executions": summary["source_executions"],
    }]}


def _theharvester_jsonl_to_legacy(report: Path) -> dict[str, list[str]]:
    payload = _read_theharvester_jsonl(report)
    return {field: payload[field] for field in ("hosts", "ips", "emails", "asns")}


def _check_theharvester_source_status(report: Path) -> str | None:
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or item.get("type") != "summary":
            continue
        executions = item.get("source_executions")
        if not isinstance(executions, list):
            continue
        failed = [
            f"{source.get('source', 'desconocida')} ({source.get('status', 'desconocido')}: {source.get('stop_reason') or source.get('error_type') or 'sin detalle'})"
            for source in executions
            if isinstance(source, dict) and source.get("status") != "completed"
        ]
        if failed:
            message = "theHarvester no completó la consulta de: " + ", ".join(failed)
            return message
    return None


def _spiderfoot_scan_id(response: httpx.Response) -> str:
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list) or len(payload) < 2 or payload[0] != "SUCCESS":
        raise RuntimeError(f"SpiderFoot no inició el escaneo: {payload!r}")
    return str(payload[1])


async def _find_spiderfoot_scan(client: httpx.AsyncClient, base_url: str, scan_name: str) -> str | None:
    """Recupera el ID si /startscan creó el proceso pero se perdió su respuesta."""
    for attempt in range(3):
        try:
            response = await client.get(f"{base_url}/scanlist", timeout=10)
            response.raise_for_status()
            rows = response.json()
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, list) and len(row) > 6 and row[1] == scan_name:
                        return str(row[0])
        except (httpx.HTTPError, ValueError):
            logger.warning("No se pudo consultar la lista de escaneos SpiderFoot", exc_info=True)
        if attempt < 2:
            await asyncio.sleep(1)
    return None


async def _stop_spiderfoot_scan(client: httpx.AsyncClient, base_url: str, scan_id: str) -> None:
    try:
        response = await client.post(f"{base_url}/stopscan", data={"id": scan_id}, timeout=10)
        response.raise_for_status()
    except httpx.HTTPError:
        logger.warning("No se pudo solicitar la detención de SpiderFoot %s", scan_id, exc_info=True)


async def run_spiderfoot(domain: str, settings: OrchestratorSettings) -> RunnerOutput:
    modules = selected_modules(domain, settings.spiderfoot_modules)
    base_url = settings.spiderfoot_url.rstrip("/")
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    scan_name = f"BaxterSec {domain} [{uuid.uuid4().hex[:12]}]"
    scan_id: str | None = None
    remote_terminal = False
    async with httpx.AsyncClient(timeout=timeout) as client:
        start_task = asyncio.create_task(client.post(
            f"{base_url}/startscan",
            data={
                "scanname": scan_name,
                "scantarget": domain,
                "modulelist": ",".join(modules),
                "typelist": "",
                "usecase": "",
            },
            headers={"Accept": "application/json"},
        ))
        try:
            try:
                scan_id = _spiderfoot_scan_id(await asyncio.shield(start_task))
            except httpx.ConnectError as error:
                raise RuntimeError(
                    "SpiderFoot no responde en SPIDERFOOT_URL. Inicia el servicio antes del análisis"
                ) from error
            deadline = asyncio.get_running_loop().time() + settings.spiderfoot_timeout_seconds
            terminal_states = {"FINISHED", "ABORTED", "ERROR-FAILED"}
            while asyncio.get_running_loop().time() < deadline:
                status_response = await client.get(
                    f"{base_url}/scanstatus", params={"id": scan_id}
                )
                status_response.raise_for_status()
                status_payload = status_response.json()
                status = (
                    str(status_payload[5]).upper()
                    if isinstance(status_payload, list) and len(status_payload) > 5
                    else ""
                )
                if status in terminal_states:
                    remote_terminal = True
                    if status != "FINISHED":
                        raise RuntimeError(f"SpiderFoot terminó con estado {status}")
                    break
                await asyncio.sleep(settings.spiderfoot_poll_seconds)
            else:
                raise TimeoutError("SpiderFoot excedió el tiempo máximo de escaneo")

            results = await client.get(
                f"{base_url}/scanexportjsonmulti", params={"ids": scan_id}
            )
            results.raise_for_status()
            payload = results.json()
        except (Exception, asyncio.CancelledError) as error:
            if scan_id is None and (isinstance(error, (asyncio.CancelledError, httpx.TimeoutException))):
                try:
                    scan_id = _spiderfoot_scan_id(await asyncio.wait_for(
                        asyncio.shield(start_task), timeout=settings.request_timeout_seconds + 5
                    ))
                except (Exception, asyncio.CancelledError):
                    scan_id = await _find_spiderfoot_scan(client, base_url, scan_name)
            if scan_id is not None and not remote_terminal:
                await _stop_spiderfoot_scan(client, base_url, scan_id)
            raise
    if not isinstance(payload, list):
        raise ValueError("SpiderFoot devolvió un formato distinto de una lista JSON")
    if not normalizar_ip(domain) and "sfp_baxter_commoncrawl" not in modules:
        payload.append(unavailable_report_event(
            "sfp_baxter_commoncrawl", domain, COMMONCRAWL_DISABLED_REASON,
        ))
    summaries = [report for report in passive_reports(payload) if report["target"] == domain]
    missing = (set(modules) & set(BAXTER_SPIDERFOOT_MODULES)) - {report["module"] for report in summaries}
    errors = [f"{report['provider']}: {report.get('error') or report['status']}"
              for report in summaries
              if report["module"] in modules
              and report["status"] not in {"ok", "empty"}]
    if missing:
        errors.append("Sin constancia de ejecución de módulos: " + ", ".join(sorted(missing))
                      + ". Comprueba que la imagen SpiderFoot incluya el perfil pasivo v1")
    return RunnerOutput(payload, error="; ".join(errors) or None,
                        failed=not any(report["status"] in {"ok", "empty", "partial"} for report in summaries))
