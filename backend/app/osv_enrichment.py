"""Enriquecimiento pasivo de paquetes explícitos mediante OSV.dev."""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Callable

import httpx

from app.nvd_enrichment import _evidence


OSV_QUERY_API = "https://api.osv.dev/v1/query"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_ECOSYSTEMS = {
    "AlmaLinux", "Alpine", "Android", "Bitnami", "crates.io", "Debian", "GIT",
    "GitHub Actions", "Go", "Hackage", "Hex", "Linux", "Maven", "npm", "NuGet",
    "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Rocky Linux", "RubyGems", "SwiftURL", "Ubuntu",
}
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_LOCK = threading.Lock()
_CACHE_SECONDS = 6 * 60 * 60


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _api_query(payload: dict[str, Any]) -> dict[str, Any]:
    key = _canonical(payload)
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    response = httpx.post(
        OSV_QUERY_API, json=payload,
        headers={"Accept": "application/json", "User-Agent": "BaxterSec/1.0 academic-passive-osint"},
        timeout=30,
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError("OSV devolvió un formato inesperado")
    with _LOCK:
        _CACHE[key] = (time.monotonic() + _CACHE_SECONDS, value)
    return value


def _package(observation: dict[str, Any]) -> tuple[str, str, str] | None:
    details = observation.get("datos") if isinstance(observation.get("datos"), dict) else {}
    package = details.get("paquete")
    ecosystem = details.get("ecosistema")
    version = details.get("version")
    if not all(isinstance(value, str) and value.strip() for value in (package, ecosystem, version)):
        return None
    if ecosystem.strip() not in _ECOSYSTEMS:
        return None
    return package.strip(), ecosystem.strip(), version.strip()


def _vulnerability(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        return None
    aliases = sorted({str(alias).upper() for alias in value.get("aliases", []) if isinstance(alias, str)})
    cve = next((alias for alias in aliases if _CVE.fullmatch(alias)), None)
    identifier = value["id"].upper()
    if _CVE.fullmatch(identifier):
        cve = identifier
    references = sorted({item.get("url") for item in value.get("references", [])
                         if isinstance(item, dict) and isinstance(item.get("url"), str)})
    severity = [item for item in value.get("severity", []) if isinstance(item, dict)]
    return {
        "id": identifier, "aliases": aliases, "cve": cve or identifier,
        "publicado_en": value.get("published"), "modificado_en": value.get("modified"),
        "retirado_en": value.get("withdrawn"), "resumen": value.get("summary"),
        "severidad": severity, "referencia": f"https://osv.dev/vulnerability/{identifier}",
        "referencias": references,
    }


def enrich_observations_osv(
    observations: list[dict[str, Any]], source: str,
    fetch: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Consulta solo evidencias con paquete, ecosistema y versión explícitos."""
    getter = fetch or _api_query
    candidates: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for observation in observations:
        package = _package(observation)
        if package is None:
            continue
        name, ecosystem, version = package
        key = (str(observation.get("tipo")), str(observation.get("valor")), ecosystem, name, version)
        candidate = candidates.setdefault(key, {
            "tipo": observation.get("tipo"), "valor": observation.get("valor"), "paquete": name,
            "ecosistema": ecosystem, "version": version, "evidencias": {},
        })
        evidence = _evidence(observation, source)
        candidate["evidencias"][_canonical(evidence)] = evidence

    queries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for candidate in candidates.values():
        query = (candidate["ecosistema"], candidate["paquete"], candidate["version"])
        if query not in queries:
            queries[query] = getter({
                "package": {"name": candidate["paquete"], "ecosystem": candidate["ecosistema"]},
                "version": candidate["version"],
            })

    findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    for candidate in candidates.values():
        payload = queries[(candidate["ecosistema"], candidate["paquete"], candidate["version"])]
        vulns = payload.get("vulns", [])
        if not isinstance(vulns, list):
            raise ValueError("OSV devolvió vulnerabilidades en un formato inesperado")
        for raw in vulns:
            osv = _vulnerability(raw)
            if osv is None:
                continue
            key = (str(candidate["tipo"]), str(candidate["valor"]), osv["cve"])
            finding = findings.setdefault(key, {
                "tipo": candidate["tipo"], "valor": candidate["valor"], "atributo": "cve",
                "datos": {
                    "cve": osv["cve"], "verificado": False, "fuente_enriquecimiento": "OSV",
                    "fuentes_enriquecimiento": ["OSV"], "coincidencia": "potencial_paquete_ecosistema_version",
                    "osv": [], "paquetes_versiones": [], "evidencias_osint": [],
                    "referencias_enriquecimiento": [],
                },
            })
            details = finding["datos"]
            details["osv"].append(osv)
            details["paquetes_versiones"].append({
                "paquete": candidate["paquete"], "ecosistema": candidate["ecosistema"],
                "version": candidate["version"],
            })
            details["evidencias_osint"].extend(candidate["evidencias"].values())
            details["referencias_enriquecimiento"].extend([osv["referencia"], *osv["referencias"]])

    result = []
    for finding in findings.values():
        details = finding["datos"]
        for field in ("osv", "paquetes_versiones", "evidencias_osint"):
            details[field] = list({_canonical(value): value for value in details[field]}.values())
        details["referencias_enriquecimiento"] = sorted(set(details["referencias_enriquecimiento"]))
        dates = [item.get("observado_en") for item in details["evidencias_osint"] if item.get("observado_en")]
        if dates:
            finding["observado_en"] = max(dates)
        result.append(finding)
    return sorted(result, key=lambda item: (str(item["tipo"]), str(item["valor"]), item["datos"]["cve"]))
