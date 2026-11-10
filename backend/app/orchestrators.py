from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from app.osint_normalization import normalizar_ip
from app.settings import DEFAULT_SPIDERFOOT_MODULES

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class OrchestratorSettings:
    shodan_api_key: str | None = None
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "certspotter,hackertarget"
    spiderfoot_url: str = "http://127.0.0.1:5001"
    spiderfoot_modules: str = DEFAULT_SPIDERFOOT_MODULES
    request_timeout_seconds: float = 30
    process_timeout_seconds: float = 900
    spiderfoot_timeout_seconds: float = 1800
    spiderfoot_poll_seconds: float = 3
    crtsh_retries: int = 4
    shodan_max_ips: int = 10
    shodan_pause_seconds: float = 1.1
    crtsh_timeout_seconds: float = 60


Runner = Callable[[str], Awaitable[Any]]
OnResult = Callable[[str, dict[str, Any]], Awaitable[None]]

# Se puede sustituir en pruebas para no esperar de verdad entre reintentos.
_sleep = asyncio.sleep
_REINTENTABLES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class RunnerOutput:
    """Resultado de un runner que, además de los datos, sabe qué IPs son del objetivo."""

    data: Any
    ips_en_alcance: tuple[str, ...] = field(default_factory=tuple)


def _error_message(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code} from {error.request.url.host}"
    if isinstance(error, httpx.RequestError):
        return f"{error.__class__.__name__} while contacting {error.request.url.host}"
    if isinstance(error, TimeoutError) and not str(error).strip():
        return "Excedió el tiempo máximo de ejecución"
    message = str(error).strip() or error.__class__.__name__
    return f"{error.__class__.__name__}: {message}"[:1000]


async def run_all(
    domain: str,
    settings: OrchestratorSettings,
    runners: dict[str, Runner] | None = None,
    on_result: OnResult | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Ejecuta todas las fuentes en paralelo y conserva el resultado de cada una.

    * Una fuente que falla nunca cancela a las demás.
    * `on_result(nombre, resultado)` se llama apenas termina CADA fuente, para
      guardar sus datos sin esperar a la más lenta.
    * `timeout_seconds` limita cuánto puede tardar cada fuente; al agotarse se
      marca como fallida.
    """
    selected_runners = runners or {
        "crt.sh": lambda target: run_crtsh(target, settings),
        "Shodan": lambda target: run_shodan(target, settings),
        "theHarvester": lambda target: run_theharvester(target, settings),
        "SpiderFoot": lambda target: run_spiderfoot(target, settings),
    }

    async def run_one(name: str, runner: Runner) -> tuple[str, dict[str, Any]]:
        try:
            if timeout_seconds:
                output = await asyncio.wait_for(runner(domain), timeout=timeout_seconds)
            else:
                output = await runner(domain)
            if isinstance(output, RunnerOutput):
                data, ips = output.data, list(output.ips_en_alcance)
            else:
                data, ips = output, []
            outcome = {"estado": "completado", "contenido": data, "error": None, "ips_en_alcance": ips}
        except Exception as error:
            outcome = {"estado": "fallido", "contenido": None, "error": _error_message(error), "ips_en_alcance": []}
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


async def run_crtsh(domain: str, settings: OrchestratorSettings) -> list[dict[str, Any]]:
    """crt.sh falla seguido bajo carga (502/504 y timeouts): se reintenta con espera creciente."""
    intentos = max(1, settings.crtsh_retries)
    timeout = httpx.Timeout(settings.crtsh_timeout_seconds, connect=min(10, settings.crtsh_timeout_seconds))
    async with httpx.AsyncClient(timeout=timeout) as client:
        for intento in range(1, intentos + 1):
            try:
                response = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"Accept": "application/json"},
                )
                if response.status_code in _REINTENTABLES and intento < intentos:
                    retry_after = response.headers.get("Retry-After") if response.status_code == 429 else None
                    delay = 30 if response.status_code == 429 and not retry_after else min(2**intento, 30)
                    if retry_after:
                        try:
                            delay = min(max(float(retry_after), delay), 60)
                        except ValueError:
                            pass
                    logger.warning("crt.sh respondió HTTP %s; reintento %s/%s en %s s", response.status_code, intento, intentos, delay)
                    await _sleep(delay)
                    continue
                response.raise_for_status()
                payload = response.json() if response.text.strip() else []
                break
            except (httpx.TimeoutException, httpx.TransportError):
                if intento == intentos:
                    raise
                await _sleep(min(2**intento, 30))
    if not isinstance(payload, list):
        raise ValueError("crt.sh devolvió un formato distinto de una lista JSON")
    return payload


async def _shodan_get(
    client: httpx.AsyncClient, path: str, params: dict[str, str], settings: OrchestratorSettings
) -> Any:
    """GET a la API de Shodan. 404 = Shodan no tiene datos de ese recurso."""
    response = await client.get(
        f"https://api.shodan.io{path}", params={**params, "key": settings.shodan_api_key}
    )
    if response.status_code == 404:
        return None
    if response.status_code == 403:
        try:
            reason = response.json().get("error", "")
        except (ValueError, AttributeError):
            reason = ""
        if isinstance(reason, str) and "membership" in reason.lower():
            raise RuntimeError(
                "El plan de Shodan requiere Membership o superior para consultar DNS y hosts"
            )
    response.raise_for_status()  # el mensaje de error nunca incluye la URL con la llave
    return response.json()


async def run_shodan(domain: str, settings: OrchestratorSettings) -> RunnerOutput:
    """Puertos y servicios de las IPs del dominio.

    Usa /dns/resolve y /shodan/host/{ip}. No usa /shodan/host/search con el
    filtro `hostname:` porque las búsquedas con filtros exigen un plan de pago.
    Shodan limita a ~1 petición por segundo.
    """
    if not settings.shodan_api_key:
        raise RuntimeError("Falta configurar SHODAN_API_KEY")

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        resolved = await _shodan_get(client, "/dns/resolve", {"hostnames": domain}, settings)
        if resolved is not None and not isinstance(resolved, dict):
            raise ValueError("Shodan devolvió un formato inesperado en /dns/resolve")

        ips: list[str] = []
        for value in (resolved or {}).values():
            ip = normalizar_ip(value) if isinstance(value, str) else None
            if ip and ip not in ips:
                ips.append(ip)
        ips = ips[: max(0, settings.shodan_max_ips)]

        hosts: list[Any] = []
        for index, ip in enumerate(ips):
            if index:
                await _sleep(settings.shodan_pause_seconds)
            host = await _shodan_get(client, f"/shodan/host/{ip}", {}, settings)
            if host is not None:
                hosts.append(host)
    return RunnerOutput(hosts, tuple(ips))


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
        if process.returncode:
            raise RuntimeError(_process_error("theHarvester", stderr, stdout))
        if jsonl_report.is_file():
            _check_theharvester_source_status(jsonl_report)
        if json_report.is_file():
            payload = json.loads(json_report.read_text(encoding="utf-8"))
            return payload
        if jsonl_report.is_file():
            payload = _theharvester_jsonl_to_legacy(jsonl_report)
            return payload
        raise RuntimeError("theHarvester terminó sin generar el reporte JSON esperado")


def _process_error(tool: str, stderr: bytes, stdout: bytes) -> str:
    detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
    return f"{tool} terminó con error" + (f": {detail[-800:]}" if detail else "")


def _theharvester_jsonl_to_legacy(report: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"hosts": [], "ips": [], "emails": [], "asns": []}
    field_by_type = {
        "hostname": "hosts",
        "host": "hosts",
        "ip": "ips",
        "email": "emails",
        "asn": "asns",
    }
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            continue
        field = field_by_type.get(str(item.get("type", "")).lower())
        value = item.get("value")
        if field and isinstance(value, str):
            result[field].append(value)
    return result


def _check_theharvester_source_status(report: Path) -> None:
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
            str(source.get("source", "desconocida"))
            for source in executions
            if isinstance(source, dict) and source.get("status") != "completed"
        ]
        if failed:
            raise RuntimeError(
                "theHarvester no completó la consulta de: " + ", ".join(failed)
            )


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


async def run_spiderfoot(domain: str, settings: OrchestratorSettings) -> list[dict[str, Any]]:
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
                "modulelist": settings.spiderfoot_modules,
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
    return payload
