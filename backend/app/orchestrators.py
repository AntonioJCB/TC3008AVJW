from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx


@dataclass(frozen=True)
class OrchestratorSettings:
    shodan_api_key: str | None = None
    theharvester_bin: str = "theHarvester"
    theharvester_sources: str = "crtsh,certspotter"
    spiderfoot_url: str = "http://127.0.0.1:5001"
    request_timeout_seconds: float = 30
    process_timeout_seconds: float = 900
    spiderfoot_timeout_seconds: float = 1800
    spiderfoot_poll_seconds: float = 3


Runner = Callable[[str], Awaitable[Any]]


def _error_message(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code} from {error.request.url.host}"
    if isinstance(error, httpx.RequestError):
        return f"{error.__class__.__name__} while contacting {error.request.url.host}"
    message = str(error).strip() or error.__class__.__name__
    return f"{error.__class__.__name__}: {message}"[:1000]


async def run_all(
    domain: str,
    settings: OrchestratorSettings,
    runners: dict[str, Runner] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run every source concurrently and retain each source's own outcome."""
    selected_runners = runners or {
        "crt.sh": lambda target: run_crtsh(target, settings),
        "Shodan": lambda target: run_shodan(target, settings),
        "theHarvester": lambda target: run_theharvester(target, settings),
        "SpiderFoot": lambda target: run_spiderfoot(target, settings),
    }

    async def run_one(name: str, runner: Runner) -> tuple[str, dict[str, Any]]:
        try:
            data = await runner(domain)
            return name, {"estado": "completado", "contenido": data, "error": None}
        except Exception as error:
            return name, {"estado": "fallido", "contenido": None, "error": _error_message(error)}

    outcomes = await asyncio.gather(
        *(run_one(name, runner) for name, runner in selected_runners.items())
    )
    return dict(outcomes)


async def run_crtsh(domain: str, settings: OrchestratorSettings) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, list):
        raise ValueError("crt.sh devolvió un formato distinto de una lista JSON")
    return payload


async def run_shodan(domain: str, settings: OrchestratorSettings) -> dict[str, Any]:
    if not settings.shodan_api_key:
        raise RuntimeError("Falta configurar SHODAN_API_KEY")

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": settings.shodan_api_key, "query": f"hostname:{domain}"},
        )
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("matches"), list):
        raise ValueError("Shodan devolvió una respuesta sin la lista 'matches'")
    return payload


async def run_theharvester(domain: str, settings: OrchestratorSettings) -> Any:
    executable = shutil.which(settings.theharvester_bin)
    if executable is None:
        raise RuntimeError(
            f"No se encontró el ejecutable '{settings.theharvester_bin}' en PATH"
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

        json_report = report_base.with_suffix(".json")
        jsonl_report = report_base.with_suffix(".jsonl")
        if json_report.is_file():
            payload = json.loads(json_report.read_text(encoding="utf-8"))
            if process.returncode:
                raise RuntimeError(_process_error("theHarvester", stderr, stdout))
            return payload
        if jsonl_report.is_file():
            payload = _theharvester_jsonl_to_legacy(jsonl_report)
            if process.returncode:
                raise RuntimeError(_process_error("theHarvester", stderr, stdout))
            return payload
        if process.returncode:
            raise RuntimeError(_process_error("theHarvester", stderr, stdout))
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


async def run_spiderfoot(domain: str, settings: OrchestratorSettings) -> list[dict[str, Any]]:
    base_url = settings.spiderfoot_url.rstrip("/")
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as client:
        started = await client.post(
            f"{base_url}/startscan",
            data={
                "scanname": f"BaxterSec {domain}",
                "scantarget": domain,
                "modulelist": "",
                "typelist": "",
                "usecase": "passive",
            },
            headers={"Accept": "application/json"},
        )
        started.raise_for_status()
        start_payload = started.json()
        if (
            not isinstance(start_payload, list)
            or len(start_payload) < 2
            or start_payload[0] != "SUCCESS"
        ):
            raise RuntimeError(f"SpiderFoot no inició el escaneo: {start_payload!r}")
        spiderfoot_scan_id = str(start_payload[1])

        deadline = asyncio.get_running_loop().time() + settings.spiderfoot_timeout_seconds
        terminal_states = {"FINISHED", "ABORTED", "ERROR-FAILED"}
        while asyncio.get_running_loop().time() < deadline:
            status_response = await client.get(
                f"{base_url}/scanstatus", params={"id": spiderfoot_scan_id}
            )
            status_response.raise_for_status()
            status_payload = status_response.json()
            status = (
                str(status_payload[5]).upper()
                if isinstance(status_payload, list) and len(status_payload) > 5
                else ""
            )
            if status in terminal_states:
                if status != "FINISHED":
                    raise RuntimeError(f"SpiderFoot terminó con estado {status}")
                break
            await asyncio.sleep(settings.spiderfoot_poll_seconds)
        else:
            raise TimeoutError("SpiderFoot excedió el tiempo máximo de escaneo")

        results = await client.get(
            f"{base_url}/scanexportjsonmulti", params={"ids": spiderfoot_scan_id}
        )
        results.raise_for_status()
        payload = results.json()
    if not isinstance(payload, list):
        raise ValueError("SpiderFoot devolvió un formato distinto de una lista JSON")
    return payload