from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shutil
import socket
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
    censys_pat: str | None = None
    censys_organization_id: str | None = None
    censys_authorized_ips: str = ""
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "certspotter,hackertarget"
    spiderfoot_url: str = "http://127.0.0.1:5001"
    spiderfoot_modules: str = DEFAULT_SPIDERFOOT_MODULES
    request_timeout_seconds: float = 30
    process_timeout_seconds: float = 900
    spiderfoot_timeout_seconds: float = 1800
    spiderfoot_poll_seconds: float = 3
    crtsh_retries: int = 4
    censys_max_ips: int = 10
    censys_pause_seconds: float = 1.1
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
        "Censys": lambda target: run_censys(target, settings),
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


async def _resolve_censys_ips(domain: str) -> list[str]:
    """DNS del sistema: no requiere créditos ni acceso al buscador Censys."""
    try:
        records = await asyncio.get_running_loop().getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise RuntimeError("Censys: no se pudo resolver el dominio por DNS público") from error
    return sorted({str(ipaddress.ip_address(row[4][0])) for row in records
                   if ipaddress.ip_address(row[4][0]).is_global})


def _censys_authorized_ips(value: str, domain: str) -> set[str]:
    try:
        scopes = json.loads(value) if value.strip() else {}
        if not isinstance(scopes, dict):
            raise ValueError
        for name, ips in scopes.items():
            if not isinstance(name, str) or not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
                raise ValueError
            # Validar toda la configuración sin incluir sus valores en errores.
            for ip in ips:
                ipaddress.ip_address(ip)
        return {str(ipaddress.ip_address(ip)) for ip in scopes.get(domain, [])}
    except (ValueError, TypeError) as error:
        raise ValueError("CENSYS_AUTHORIZED_IPS debe ser JSON: dominio canónico -> lista de IPs literales") from error


async def run_censys(domain: str, settings: OrchestratorSettings) -> RunnerOutput:
    """Lookup Platform v3, disponible para Free según permisos/créditos.

    Guarda respuestas originales. DNS relaciona un host; solo la lista explícita
    del servidor autoriza atribuir servicios de esa IP al cliente.
    """
    if not settings.censys_pat:
        raise RuntimeError("Falta configurar CENSYS_PAT (Personal Access Token de Censys Platform)")
    if settings.censys_max_ips < 1 or settings.censys_pause_seconds < 0:
        raise ValueError("CENSYS_MAX_IPS debe ser positivo y CENSYS_PAUSE_SECONDS no negativo")
    allowed = _censys_authorized_ips(settings.censys_authorized_ips, domain)
    ips = await asyncio.wait_for(_resolve_censys_ips(domain), settings.request_timeout_seconds)
    if not ips:
        raise RuntimeError("Censys: el dominio no tiene IPs públicas consultables")
    if len(ips) > settings.censys_max_ips:
        raise RuntimeError("Censys: las IPs del dominio exceden CENSYS_MAX_IPS; revisa el límite y tus créditos")
    headers = {"Authorization": f"Bearer {settings.censys_pat}",
               "Accept": "application/vnd.censys.api.v3.host.v1+json"}
    params = {"organization_id": settings.censys_organization_id} if settings.censys_organization_id else {}
    hosts: list[Any] = []
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        for index, ip in enumerate(ips):
            if index:
                await _sleep(settings.censys_pause_seconds)
            response = await client.get(f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                                        headers=headers, params=params)
            if response.status_code == 404:
                continue  # API respondió: no tiene un registro para esta IP.
            errors = {
                401: "Censys HTTP 401: CENSYS_PAT no es válido o ha expirado",
                402: "Censys HTTP 402: revisa los créditos disponibles de la cuenta",
                403: "Censys HTTP 403: la cuenta u organización no tiene acceso al lookup de hosts",
                429: "Censys HTTP 429: límite de peticiones o concurrencia; espera y revisa tu cuota",
            }
            if response.status_code in errors:
                raise RuntimeError(errors[response.status_code])
            response.raise_for_status()
            try:
                payload = response.json()
                host = payload["result"]["resource"]
                if not isinstance(host, dict) or normalizar_ip(str(host.get("ip", ""))) != ip:
                    raise ValueError
                if host.get("truncated") or (host.get("services") is not None and not isinstance(host["services"], list)):
                    raise ValueError
                count = host.get("service_count")
                if isinstance(count, int) and count > len(host.get("services") or []):
                    raise ValueError
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError("Censys devolvió un host incompleto o un formato Platform v3 inesperado") from error
            hosts.append(payload)
    return RunnerOutput({"hosts": hosts, "dns": {"dominio": domain, "ips": ips}},
                        tuple(ip for ip in ips if ip in allowed))


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
