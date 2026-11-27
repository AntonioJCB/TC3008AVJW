"""Enriquecimiento pasivo producto/versión -> CPE -> CVE mediante NVD 2.0."""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Callable

import httpx


CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_VERSION = re.compile(r"\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9]+)*")
_CACHE: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()
_REQUEST_LOCK = threading.Lock()
_LAST_REQUEST = 0.0
_CACHE_SECONDS = 6 * 60 * 60
_MIN_INTERVAL_SECONDS = 0.7
_PRODUCT_ALIASES = {
    "apache": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "microsoft-iis": "Microsoft Internet Information Services",
    "microsoft iis": "Microsoft Internet Information Services",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _api_get(api_key: str, url: str, params: dict[str, Any]) -> dict[str, Any]:
    """GET cacheado y serializado para respetar la cuota oficial con API key."""
    global _LAST_REQUEST
    key = (url, _canonical(params))
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] > now:
            return cached[1]
    with _REQUEST_LOCK:
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
            if cached and cached[0] > time.monotonic():
                return cached[1]
        wait = _MIN_INTERVAL_SECONDS - (time.monotonic() - _LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        response = httpx.get(
            url,
            params=params,
            headers={"Accept": "application/json", "User-Agent": "BaxterSec/1.0 academic-passive-osint", "apiKey": api_key},
            timeout=30,
        )
        _LAST_REQUEST = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("NVD devolvió un formato inesperado")
        with _CACHE_LOCK:
            _CACHE[key] = (time.monotonic() + _CACHE_SECONDS, payload)
        return payload


def _cpe_parts(value: str) -> list[str]:
    if value.startswith("cpe:/"):
        legacy = value[5:].split(":")
        legacy.extend(["*"] * (11 - len(legacy)))
        return legacy[:11]
    if not value.startswith("cpe:2.3:"):
        return []
    parts, current, escaped = [], "", False
    for character in value[8:]:
        if escaped:
            current += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append(current)
            current = ""
        else:
            current += character
    parts.append(current)
    return parts if len(parts) == 11 else []


def _to_cpe23(value: str) -> str | None:
    parts = _cpe_parts(value)
    if len(parts) != 11 or parts[0] not in {"a", "h", "o"}:
        return None
    if value.startswith("cpe:2.3:"):
        return value
    return "cpe:2.3:" + ":".join(parts)


def _product_version(observation: dict[str, Any]) -> tuple[str, str, tuple[str, ...]] | None:
    details = observation.get("datos") if isinstance(observation.get("datos"), dict) else {}
    product = details.get("producto")
    version = details.get("version")
    cpes = details.get("cpe") if isinstance(details.get("cpe"), list) else []
    normalized_cpes = tuple(sorted(filter(None, (_to_cpe23(str(value)) for value in cpes))))
    if isinstance(product, str) and isinstance(version, str) and product.strip() and version.strip():
        selected_product = _PRODUCT_ALIASES.get(product.strip().lower(), product.strip())
        return selected_product, version.strip(), normalized_cpes
    if observation.get("atributo") != "info_host" or details.get("tipo_evento") not in {
        "WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY", "SOFTWARE_USED",
    }:
        return None
    value = details.get("valor")
    if not isinstance(value, str):
        return None
    direct_cpe = _to_cpe23(value.strip())
    if direct_cpe:
        parts = _cpe_parts(direct_cpe)
        if parts[2] not in {"", "*", "-"} and parts[3] not in {"", "*", "-"}:
            return parts[2].replace("_", " "), parts[3], (direct_cpe,)
        return None
    match = _VERSION.search(value)
    if not match:
        return None
    product = value[:match.start()].rstrip(" /_vV-").strip()
    if not product or product.lower() in {"server", "web server", "unknown"}:
        return None
    product = _PRODUCT_ALIASES.get(product.lower(), product)
    return product, match.group(0), ()


def _evidence(observation: dict[str, Any], source: str) -> dict[str, Any]:
    details = observation.get("datos") if isinstance(observation.get("datos"), dict) else {}
    evidence = {
        "fuente": source,
        "atributo": observation.get("atributo"),
        "observado_en": observation.get("observado_en"),
        "tipo_evento": details.get("tipo_evento"),
        "modulo": details.get("modulo"),
        "proveedor": details.get("proveedor"),
        "valor": details.get("valor"),
        "primera_observacion": details.get("primera_observacion"),
        "ultima_observacion": details.get("ultima_observacion"),
        "referencias": details.get("referencias") if isinstance(details.get("referencias"), list) else [],
    }
    return {key: value for key, value in evidence.items() if value not in (None, [], "")}


def _candidate_cpes(payload: dict[str, Any], product: str, version: str) -> list[str]:
    tokens = [token for token in re.findall(r"[a-z0-9]+", product.lower()) if len(token) > 1]
    matches = []
    for item in payload.get("products", []):
        cpe = item.get("cpe") if isinstance(item, dict) else None
        if not isinstance(cpe, dict) or cpe.get("deprecated") is True:
            continue
        name = cpe.get("cpeName")
        parts = _cpe_parts(name) if isinstance(name, str) else []
        titles = " ".join(str(title.get("title", "")) for title in cpe.get("titles", []) if isinstance(title, dict)).lower()
        haystack = " ".join([titles, parts[1] if len(parts) == 11 else "", parts[2] if len(parts) == 11 else ""]).replace("_", " ")
        if len(parts) == 11 and parts[3].lower() == version.lower() and all(token in haystack for token in tokens):
            matches.append(name)
    return sorted(set(matches))[:3]


def _cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(family)
        if not isinstance(values, list) or not values:
            continue
        metric = values[0] if isinstance(values[0], dict) else {}
        data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        return {key: value for key, value in {
            "version": data.get("version"), "puntaje_base": data.get("baseScore"),
            "severidad": data.get("baseSeverity") or metric.get("baseSeverity"),
        }.items() if value is not None}
    return {}


def _cves(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") if isinstance(item, dict) else None
        identifier = cve.get("id") if isinstance(cve, dict) else None
        if not isinstance(identifier, str) or not _CVE.fullmatch(identifier):
            continue
        descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
        description = next((entry.get("value") for entry in descriptions
                            if isinstance(entry, dict) and entry.get("lang") == "en"), None)
        result.append({
            "cve": identifier.upper(), "publicado_en": cve.get("published"),
            "modificado_en": cve.get("lastModified"), "estado": cve.get("vulnStatus"),
            "descripcion": description[:500] if isinstance(description, str) else None,
            "cvss": _cvss(cve), "referencia": f"https://nvd.nist.gov/vuln/detail/{identifier.upper()}",
        })
    return result


def enrich_observations(
    observations: list[dict[str, Any]], api_key: str, source: str,
    fetch: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Devuelve CVE potenciales; nunca verificadas ni aptas para puntuar por sí solas."""
    if not api_key:
        return []
    getter = fetch or (lambda url, params: _api_get(api_key, url, params))
    local_cache: dict[tuple[str, str], dict[str, Any]] = {}

    def get(url: str, params: dict[str, Any]) -> dict[str, Any]:
        key = (url, _canonical(params))
        if key not in local_cache:
            local_cache[key] = getter(url, params)
        return local_cache[key]

    candidates: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for observation in observations:
        parsed = _product_version(observation)
        if parsed is None:
            continue
        product, version, cpes = parsed
        key = (str(observation.get("tipo")), str(observation.get("valor")), product.lower(), version.lower())
        candidate = candidates.setdefault(key, {
            "tipo": observation.get("tipo"), "valor": observation.get("valor"),
            "producto": product, "version": version, "cpes": set(cpes), "evidencias": {},
        })
        evidence = _evidence(observation, source)
        candidate["evidencias"][_canonical(evidence)] = evidence

    findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    for candidate in list(candidates.values())[:10]:
        cpes = sorted(candidate["cpes"])
        if not cpes:
            payload = get(CPE_API, {"keywordSearch": f"{candidate['producto']} {candidate['version']}", "resultsPerPage": 20})
            cpes = _candidate_cpes(payload, candidate["producto"], candidate["version"])
        for cpe in cpes:
            payload = get(CVE_API, {"cpeName": cpe, "isVulnerable": "", "resultsPerPage": 200})
            truncated = int(payload.get("totalResults") or 0) > len(payload.get("vulnerabilities") or [])
            for cve in _cves(payload):
                key = (str(candidate["tipo"]), str(candidate["valor"]), cve["cve"])
                finding = findings.setdefault(key, {
                    "tipo": candidate["tipo"], "valor": candidate["valor"], "atributo": "cve",
                    "datos": {
                        "cve": cve["cve"], "verificado": False,
                        "fuente_enriquecimiento": "NVD", "coincidencia": "potencial_producto_version",
                        "fuentes_enriquecimiento": ["NVD"],
                        "referencias_enriquecimiento": [cve["referencia"]],
                        "nvd": cve, "productos_versiones": {}, "evidencias_osint": {},
                    },
                })
                product_key = _canonical({"producto": candidate["producto"], "version": candidate["version"], "cpe": cpe})
                finding["datos"]["productos_versiones"][product_key] = {
                    "producto": candidate["producto"], "version": candidate["version"], "cpe": cpe,
                    "resultados_nvd_truncados": truncated,
                }
                finding["datos"]["evidencias_osint"].update(candidate["evidencias"])

    result = []
    for finding in findings.values():
        finding["datos"]["productos_versiones"] = list(finding["datos"]["productos_versiones"].values())
        finding["datos"]["evidencias_osint"] = list(finding["datos"]["evidencias_osint"].values())
        dates = [evidence.get("observado_en") for evidence in finding["datos"]["evidencias_osint"] if evidence.get("observado_en")]
        if dates:
            finding["observado_en"] = max(dates)
        result.append(finding)
    return sorted(result, key=lambda item: (str(item["tipo"]), str(item["valor"]), item["datos"]["cve"]))
