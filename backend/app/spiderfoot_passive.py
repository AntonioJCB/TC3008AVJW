"""Shared by backend and SpiderFoot. Provider lookups only; never probes targets."""
from __future__ import annotations

import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode, urlsplit

MODULES = {
    "sfp_baxter_dns_doh": "google_dns_doh",
    "sfp_baxter_urlscan": "urlscan",
    "sfp_baxter_commoncrawl": "common_crawl",
    "sfp_baxter_rdap": "rdap",
}
PASSIVE_DNS_MODULES = ("sfp_dnsresolve", "sfp_dnsraw", "sfp_robtex", "sfp_crobat_api")
LEGACY_MODULES = ",".join(PASSIVE_DNS_MODULES)
PREVIOUS_DEFAULT_MODULES = ",".join((*PASSIVE_DNS_MODULES, "sfp_baxter_urlscan"))
DNS_URLSCAN_DEFAULT_MODULES = ",".join((*PASSIVE_DNS_MODULES, "sfp_baxter_dns_doh", "sfp_baxter_urlscan"))
COMMONCRAWL_DEFAULT_MODULES = ",".join((*PASSIVE_DNS_MODULES, "sfp_baxter_dns_doh", "sfp_baxter_urlscan", "sfp_baxter_commoncrawl"))
COMMONCRAWL_RDAP_DEFAULT_MODULES = ",".join((*PASSIVE_DNS_MODULES, "sfp_baxter_dns_doh", "sfp_baxter_urlscan", "sfp_baxter_commoncrawl", "sfp_baxter_rdap"))
# El CDX público devolvió 504 persistentes incluso con concurrencia y plazo acotados.
# Se conserva el adaptador para pruebas manuales, pero se retira temporalmente del perfil predeterminado.
DEFAULT_MODULES = ",".join((*PASSIVE_DNS_MODULES, "sfp_baxter_dns_doh", "sfp_baxter_urlscan", "sfp_baxter_rdap"))
COMMONCRAWL_DISABLED_REASON = (
    "Common Crawl está deshabilitado temporalmente: su API CDX devolvió HTTP 504 "
    "de forma reiterada; el activo no fue evaluado por esta capacidad."
)
PROFILE = "baxter-passive-v1"

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}
DNS_QUERIES = (
    ("a", "A", "target"), ("aaaa", "AAAA", "target"),
    ("cname", "CNAME", "target"), ("mx", "MX", "target"),
    ("txt", "TXT", "target"), ("caa", "CAA", "target"),
    ("ns", "NS", "target"), ("soa", "SOA", "target"),
    ("ds", "DS", "target"), ("dmarc", "TXT", "_dmarc"),
    ("mta_sts", "TXT", "_mta-sts"), ("tls_rpt", "TXT", "_smtp._tls"),
)


def selected_modules(target, configured=DEFAULT_MODULES):
    # Upgrade the previous preset, but never accept arbitrary active plugins.
    preset = DEFAULT_MODULES if configured in {
        LEGACY_MODULES, PREVIOUS_DEFAULT_MODULES, DNS_URLSCAN_DEFAULT_MODULES,
        COMMONCRAWL_DEFAULT_MODULES, COMMONCRAWL_RDAP_DEFAULT_MODULES,
    } else configured
    names = [name.strip() for name in preset.split(",") if name.strip()]
    # Mientras el CDX público siga inestable, Common Crawl solo puede ejecutarse
    # de forma aislada para pruebas controladas, nunca dentro del perfil normal.
    if len(names) > 1:
        names = [name for name in names if name != "sfp_baxter_commoncrawl"]
    allowed = {*MODULES, *PASSIVE_DNS_MODULES}
    if not names or any(name not in allowed for name in names):
        raise ValueError("SPIDERFOOT_MODULES debe contener únicamente módulos Baxter pasivos revisados")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise ValueError("SpiderFoot solo admite IP públicas autorizadas")
    ip_providers = set()
    domain_providers = {"urlscan", "google_dns_doh", "common_crawl", "rdap"}
    selected = [name for name in dict.fromkeys(names) if (
        name in MODULES and MODULES[name] in ip_providers if address
        else name in PASSIVE_DNS_MODULES or (name in MODULES and MODULES[name] in domain_providers)
    )]
    if not selected:
        raise ValueError("No hay módulos pasivos compatibles configurados para este objetivo")
    return selected


def reports(raw):
    """Read only versioned envelopes from our plugins, with exact target attribution."""
    result = []
    chunks = {}
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict) or row.get("module") not in MODULES:
            continue
        if str(row.get("false_positive", "")).strip().lower() in {"1", "true"}:
            continue
        if row.get("event_type", row.get("type")) != "RAW_RIR_DATA":
            continue
        try:
            value = json.loads(row.get("data", ""))
        except (TypeError, ValueError):
            continue
        if (not isinstance(value, dict) or value.get("profile") != PROFILE
                or value.get("provider") != MODULES[row["module"]]
                or value.get("target") != row.get("scan_target")
                or value.get("status") not in {"ok", "empty", "partial", "error", "unavailable"}
                or not isinstance(value.get("events"), list)):
            continue
        chunk_type = value.get("chunk_type")
        if chunk_type in {"summary", "dns_check", "provider_event", "report_fragment"}:
            key = (row["module"], value["target"], value.get("checked_at"))
            group = chunks.setdefault(key, {
                "summary": None, "checks": [], "events": [], "event_fragments": {},
                "report_fragments": {}, "fragment_meta": None,
            })
            if chunk_type == "summary" and group["summary"] is None:
                group["summary"] = value
            elif chunk_type == "dns_check" and isinstance(value.get("check"), dict):
                group["checks"].append(value["check"])
            elif chunk_type == "provider_event" and isinstance(value.get("provider_event"), dict):
                group["events"].append(value["provider_event"])
            elif (chunk_type == "provider_event" and type(value.get("event_index")) is int
                  and type(value.get("fragment_index")) is int and type(value.get("fragment_count")) is int
                  and isinstance(value.get("event_fragment"), str)):
                fragments = group["event_fragments"].setdefault(value["event_index"], {})
                fragments[value["fragment_index"]] = (value["fragment_count"], value["event_fragment"])
            elif (chunk_type == "report_fragment" and type(value.get("fragment_index")) is int
                  and type(value.get("fragment_count")) is int
                  and isinstance(value.get("report_fragment"), str)):
                group["fragment_meta"] = group["fragment_meta"] or value
                group["report_fragments"][value["fragment_index"]] = (
                    value["fragment_count"], value["report_fragment"]
                )
            continue
        result.append({**value, "module": row["module"]})
    for (module, _target, _checked_at), group in chunks.items():
        if group["report_fragments"]:
            fragments = group["report_fragments"]
            expected_parts = next(iter(fragments.values()))[0]
            complete = len(fragments) == expected_parts and set(fragments) == set(range(expected_parts))
            report = None
            if complete:
                try:
                    report = json.loads("".join(fragments[part][1] for part in range(expected_parts)))
                except (TypeError, ValueError):
                    report = None
            if (isinstance(report, dict) and report.get("profile") == PROFILE
                    and report.get("provider") == MODULES[module]
                    and report.get("target") == _target
                    and report.get("status") in {"ok", "empty", "partial", "error", "unavailable"}
                    and isinstance(report.get("events"), list)):
                result.append({**report, "module": module})
            else:
                meta = group["fragment_meta"] or {}
                result.append({
                    "profile": PROFILE, "provider": MODULES[module], "target": _target,
                    "status": "partial", "query": "", "events": [], "results": 0,
                    "checked_at": _checked_at, "limitations": [
                        "El reporte del proveedor quedó incompleto durante la exportación de SpiderFoot."
                    ], "module": module,
                    "error": f"Solo se recuperaron {len(fragments)} de {expected_parts} fragmentos del reporte",
                })
            continue
        summary = group["summary"]
        if not isinstance(summary, dict):
            continue
        report = {key: value for key, value in summary.items() if key not in {"chunk_type", "check_count", "event_count"}}
        report["module"] = module
        report["checks"] = group["checks"]
        report["events"] = group["events"]
        for index in sorted(group["event_fragments"]):
            fragments = group["event_fragments"][index]
            expected_parts = next(iter(fragments.values()))[0] if fragments else 0
            if len(fragments) != expected_parts or set(fragments) != set(range(expected_parts)):
                continue
            try:
                event = json.loads("".join(fragments[part][1] for part in range(expected_parts)))
            except (TypeError, ValueError):
                continue
            if isinstance(event, dict):
                report["events"].append(event)
        for check in report["checks"]:
            _dns_check_event(report, check)
        expected = summary.get("check_count")
        if type(expected) is int and expected != len(report["checks"]):
            report["status"] = "partial"
            report["error"] = f"Solo se recuperaron {len(report['checks'])} de {expected} comprobaciones DNS"
            report.setdefault("limitations", []).append("El reporte DNS quedó incompleto durante la exportación de SpiderFoot.")
        expected_events = summary.get("event_count")
        if type(expected_events) is int and expected_events != len(report["events"]):
            report["status"] = "partial"
            report["error"] = f"Solo se recuperaron {len(report['events'])} de {expected_events} evidencias del proveedor"
            report.setdefault("limitations", []).append("El reporte del proveedor quedó incompleto durante la exportación de SpiderFoot.")
        result.append(report)
    return result


_EVENT_DATA_LIMIT = 900


def serialize_report_chunk(value):
    """JSON válido sin dominios literales que otros módulos puedan reinterpretar."""
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    escaped = []
    in_string = False
    previous_escape = False
    for character in serialized:
        if in_string and character == "." and not previous_escape:
            escaped.append("\\u002e")
            continue
        escaped.append(character)
        if not in_string:
            if character == '"':
                in_string = True
            continue
        if previous_escape:
            previous_escape = False
        elif character == "\\":
            previous_escape = True
        elif character == '"':
            in_string = False
    return "".join(escaped)


def unavailable_report_event(module, target, reason):
    """Registra una capacidad deshabilitada sin simular una consulta ni un resultado vacío."""
    report = {
        "profile": PROFILE, "provider": MODULES[module], "target": target,
        "status": "unavailable", "query": "", "events": [], "results": 0,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "limitations": [reason], "error": reason, "disabled": True,
    }
    return {
        "event_type": "RAW_RIR_DATA", "data": serialize_report_chunk(report),
        "module": module, "source_data": target, "scan_target": target,
        "false_positive": 0,
    }


def _bounded_report_chunks(report, chunks):
    """Keep every emitted event below SpiderFoot's 1024-character data limit."""
    if all(len(serialize_report_chunk(chunk)) <= _EVENT_DATA_LIMIT for chunk in chunks):
        return chunks
    serialized = json.dumps(report, separators=(",", ":"), ensure_ascii=False)
    base = {
        "profile": report["profile"], "provider": report["provider"], "target": report["target"],
        "status": report["status"], "query": "", "events": [], "results": 0,
        "checked_at": report["checked_at"], "limitations": [], "chunk_type": "report_fragment",
    }
    fragments = []
    offset = 0
    while offset < len(serialized):
        size = min(400, len(serialized) - offset)
        while True:
            candidate = {**base, "fragment_index": len(fragments), "fragment_count": 999999,
                         "report_fragment": serialized[offset:offset + size]}
            if len(serialize_report_chunk(candidate)) <= _EVENT_DATA_LIMIT:
                break
            if size == 1:
                raise ValueError("No fue posible fragmentar el reporte pasivo")
            size //= 2
        fragments.append(serialized[offset:offset + size])
        offset += size
    count = len(fragments)
    return [{**base, "fragment_index": index, "fragment_count": count, "report_fragment": fragment}
            for index, fragment in enumerate(fragments)]


def report_chunks(report):
    """Split verbose reports into small SpiderFoot events."""
    if report.get("provider") in {"urlscan", "common_crawl", "rdap"} and isinstance(report.get("events"), list):
        summary = {key: value for key, value in report.items() if key not in {"events", "response"}}
        summary.update(chunk_type="summary", event_count=len(report["events"]), events=[])
        chunks = [summary]
        for event_index, event in enumerate(report["events"]):
            serialized = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
            fragments = [serialized[start:start + 600] for start in range(0, len(serialized), 600)] or [""]
            for fragment_index, fragment in enumerate(fragments):
                chunks.append({
                    "profile": report["profile"], "provider": report["provider"], "target": report["target"],
                    "status": report["status"], "query": "", "events": [], "results": 0,
                    "checked_at": report["checked_at"], "limitations": [], "chunk_type": "provider_event",
                    "event_index": event_index, "fragment_index": fragment_index,
                    "fragment_count": len(fragments), "event_fragment": fragment,
                })
        return _bounded_report_chunks(report, chunks)
    if report.get("provider") != "google_dns_doh" or not isinstance(report.get("checks"), list):
        return _bounded_report_chunks(report, [report])
    summary = {key: value for key, value in report.items() if key not in {"checks", "events", "queries", "response"}}
    summary.update(chunk_type="summary", check_count=len(report["checks"]), events=[])
    chunks = [summary]
    for check in report["checks"]:
        chunks.append({
            "profile": report["profile"], "provider": report["provider"], "target": report["target"],
            "status": report["status"], "query": "", "events": [], "results": 0,
            "checked_at": report["checked_at"], "limitations": [],
            "chunk_type": "dns_check", "check": check,
        })
    return _bounded_report_chunks(report, chunks)


def _strings(value):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("Lista de cadenas inválida")
    return value


def collect(provider, target, fetch, *, api_key="",
            commoncrawl_indexes=2, commoncrawl_max_results=50, registrable_domain="",
            urlscan_detail_limit=3, urlscan_headers_max_age_days=90,
            commoncrawl_deadline_seconds=35, commoncrawl_retry_delay_seconds=0.5):
    """fetch(url, params) -> (HTTP status, decoded JSON). Credentials never enter output."""
    report = {"profile": PROFILE, "provider": provider, "target": target,
              "status": "error", "query": "", "events": [], "results": 0,
              "checked_at": datetime.now(timezone.utc).isoformat(), "limitations": []}
    try:
        module = next(name for name, value in MODULES.items() if value == provider)
        selected_modules(target, module)
        if provider == "google_dns_doh":
            _dns_doh(fetch, report)
            return report
        if provider == "common_crawl":
            if not re.fullmatch(r"[a-zA-Z0-9_.-]+", target):
                raise ValueError("Nombre de dominio inválido")
            _commoncrawl(
                fetch, report, int(commoncrawl_indexes), int(commoncrawl_max_results),
                float(commoncrawl_deadline_seconds), float(commoncrawl_retry_delay_seconds),
            )
            return report
        if provider == "rdap":
            _rdap(fetch, report, registrable_domain)
            return report
        if provider == "urlscan":
            if not re.fullmatch(r"[a-zA-Z0-9_.-]+", target):
                raise ValueError("Nombre de dominio inválido")
            url = "https://urlscan.io/api/v1/search/"
            params = {
                "q": f'(page.domain.keyword:"{target}" OR task.domain.keyword:"{target}")',
                "size": 100,
                "datasource": "scans",
            }
            report["query"] = url + "?" + urlencode(params)
            report["authenticated"] = bool(api_key)
        else:
            raise ValueError("Proveedor pasivo no admitido")
        code, data = fetch(url, params)
        report["http_status"] = code
        if code != 200:
            report["error"] = f"Proveedor respondió HTTP {code}; consulta no completada"
            return report
        if not isinstance(data, dict):
            raise ValueError("Respuesta no es un objeto JSON")
        if provider != "urlscan":
            report["response"] = data
        if provider == "urlscan":
            _urlscan(data, report, fetch=fetch if api_key else None,
                     detail_limit=int(urlscan_detail_limit),
                     headers_max_age_days=int(urlscan_headers_max_age_days))
        else:
            raise ValueError("Proveedor pasivo no admitido")
        if report["status"] == "error":
            report["status"] = "ok" if report["results"] else "empty"
    except Exception:
        # Do not leak URLs containing keys or credentials from request exceptions.
        report.update(status="error", error="No fue posible obtener o validar la respuesta del proveedor", events=[], results=0)
    return report


def _dns_name(value):
    return str(value or "").strip().lower().rstrip(".")


def _txt_value(value):
    """Join quoted DNS presentation segments without altering stored evidence."""
    value = str(value or "").strip()
    parts = re.findall(r'"((?:\\.|[^"\\])*)"', value)
    if not parts:
        return value
    return "".join(part.replace(r'\"', '"').replace(r"\\", "\\") for part in parts)


def _issue(code, message, *, evaluable=False, severity="informativa", rule=None):
    return {"code": code, "message": message, "severity": severity,
            "evaluable": evaluable, "rule": rule}


def _dns_query(fetch, report, check_id, rrtype, name, *, skip_reason=None):
    url = "https://dns.google/resolve"
    params = {"name": name, "type": rrtype, "do": "1", "cd": "0", "edns_client_subnet": "0.0.0.0/0"}
    query = url + "?" + urlencode(params)
    check = {"check": check_id, "name": name, "rrtype": rrtype, "state": "error",
             "records": [], "dnssec_validated": None, "rcode": None,
             "checked_at": report["checked_at"], "query": query, "interpretation": "",
             "issues": []}
    if skip_reason:
        check["error_type"] = "provider_circuit_open"
        check["interpretation"] = (
            "Consulta omitida después de fallos consecutivos del proveedor: " + skip_reason
        )
        return check
    try:
        code, data = fetch(url, params)
        check["http_status"] = code
        if code != 200:
            check["error_type"] = f"http_{code}"
            check["interpretation"] = f"Google Public DNS respondió HTTP {code}; el registro no pudo verificarse."
            return check
        if not isinstance(data, dict) or type(data.get("Status")) is not int:
            check["error_type"] = "invalid_response"
            check["interpretation"] = "La respuesta DNS no tuvo el formato esperado; el registro no pudo verificarse."
            return check
        check["rcode"] = data["Status"]
        check["dnssec_validated"] = data.get("AD") is True
        if data["Status"] not in {0, 3}:
            check["interpretation"] = f"La resolución devolvió RCODE {data['Status']}; el registro no pudo verificarse."
            return check
        answers = data.get("Answer", [])
        if answers is None:
            answers = []
        if not isinstance(answers, list):
            check["interpretation"] = "La sección Answer no tuvo el formato esperado; el registro no pudo verificarse."
            return check
        expected_type = DNS_TYPES[rrtype]
        for answer in answers:
            if (not isinstance(answer, dict) or _dns_name(answer.get("name")) != _dns_name(name)
                    or answer.get("type") != expected_type or not isinstance(answer.get("data"), str)):
                continue
            check["records"].append({"name": _dns_name(answer["name"]), "type": rrtype,
                                     "ttl": answer.get("TTL"), "data": answer["data"]})
        check["state"] = "present" if check["records"] else "absent"
        check["interpretation"] = (f"Se encontraron {len(check['records'])} registros {rrtype} exactos."
                                   if check["records"] else f"La consulta fue concluyente y no devolvió registros {rrtype} exactos.")
    except Exception as error:
        check["error_type"] = error.__class__.__name__
        check["interpretation"] = "No fue posible consultar o validar este registro mediante Google Public DNS."
    return check


def _dns_interpret(checks, target):
    by_id = {check["check"]: check for check in checks}
    mx = by_id["mx"]
    mx_values = [str(record["data"]).strip() for record in mx["records"]]
    mail_enabled = mx["state"] == "present" and not (len(mx_values) == 1 and re.fullmatch(r"0\s+\.?", mx_values[0]))
    mx["mail_enabled"] = mail_enabled
    if mx["state"] == "present":
        mx["interpretation"] = ("El dominio publica un registro MX nulo y declara que no recibe correo."
                                if not mail_enabled else "El dominio publica servidores para recepción de correo; sus destinos no se incorporan como activos del cliente.")

    txt = by_id["txt"]
    spf_records = [record for record in txt["records"] if _txt_value(record["data"]).lower().startswith("v=spf1")]
    spf = {"check": "spf", "name": target, "rrtype": "TXT", "state": "present" if spf_records else txt["state"],
           "records": spf_records, "dnssec_validated": txt["dnssec_validated"], "rcode": txt["rcode"],
           "checked_at": txt["checked_at"], "query": txt["query"], "issues": [], "mail_enabled": mail_enabled,
           "interpretation": ""}
    if txt["state"] == "error":
        spf.update(state="error", interpretation="La consulta TXT falló; SPF no pudo verificarse.")
    elif not spf_records:
        spf["interpretation"] = ("No se encontró una política SPF exacta. Como el activo publica MX, la ausencia queda preparada como evidencia candidata de CONF-003."
                                 if mail_enabled else "No se encontró una política SPF exacta, pero no hay evidencia de que este nombre envíe correo; no se genera riesgo.")
        if mail_enabled:
            spf["issues"].append(_issue("SPF_MISSING", "No existe SPF exacto para un nombre con recepción de correo.", evaluable=True, severity="media", rule="CONF-003"))
    else:
        policies = [_txt_value(record["data"]) for record in spf_records]
        spf["interpretation"] = "Se encontró una política SPF exacta y se evaluaron sus mecanismos terminales."
        if len(policies) > 1:
            spf["issues"].append(_issue("SPF_MULTIPLE", "Existen múltiples políticas SPF; los receptores pueden tratarlas como error permanente.", evaluable=True, severity="media", rule="CONF-003"))
        for policy in policies:
            lower = policy.lower()
            if re.search(r"(?:^|\s)\+all(?:\s|$)", lower):
                spf["issues"].append(_issue("SPF_ALLOW_ALL", "SPF autoriza explícitamente a cualquier origen mediante +all.", evaluable=True, severity="alta", rule="CONF-003"))
            elif re.search(r"(?:^|\s)\?all(?:\s|$)", lower):
                spf["issues"].append(_issue("SPF_NEUTRAL_ALL", "SPF termina en ?all y no rechaza orígenes no autorizados.", evaluable=True, severity="media", rule="CONF-003"))
            elif re.search(r"(?:^|\s)~all(?:\s|$)", lower):
                spf["issues"].append(_issue(
                    "SPF_SOFTFAIL_ALL",
                    "SPF termina en ~all (softfail); requiere revisión contextual."
                    if mail_enabled else
                    "SPF termina en ~all, pero no existe evidencia de recepción de correo; se conserva como información.",
                    evaluable=mail_enabled, severity="baja", rule="CONF-003",
                ))
            elif not re.search(r"(?:^|\s)-all(?:\s|$)", lower):
                spf["issues"].append(_issue("SPF_NO_TERMINAL_ALL", "SPF no contiene un mecanismo all terminal explícito.", evaluable=True, severity="media", rule="CONF-003"))
    checks.append(spf)

    dmarc = by_id["dmarc"]
    dmarc_records = [record for record in dmarc["records"] if _txt_value(record["data"]).lower().startswith("v=dmarc1")]
    if dmarc["state"] == "present" and not dmarc_records:
        dmarc["state"] = "unverified"
        dmarc["interpretation"] = "Se encontraron TXT en el nombre DMARC, pero ninguno contiene una política DMARC válida."
        dmarc["issues"].append(_issue("DMARC_MALFORMED", "El TXT de _dmarc no contiene una política DMARC reconocible.", evaluable=True, severity="media", rule="CONF-003"))
    elif dmarc["state"] == "absent":
        dmarc["state"] = "unverified"
        dmarc["interpretation"] = "No existe DMARC exacto; no se afirma ausencia efectiva porque una política del dominio organizacional podría heredarse."
    elif dmarc_records:
        dmarc["records"] = dmarc_records
        policies = [_txt_value(record["data"]).lower() for record in dmarc_records]
        parsed_policies = []
        dmarc["interpretation"] = "Se encontró una política DMARC exacta y se evaluaron p y pct."
        if len(policies) > 1:
            dmarc["issues"].append(_issue("DMARC_MULTIPLE", "Existen múltiples políticas DMARC en el mismo nombre.", evaluable=True, severity="media", rule="CONF-003"))
        for policy in policies:
            tags = {part.split("=", 1)[0].strip(): part.split("=", 1)[1].strip()
                    for part in policy.split(";") if "=" in part}
            parsed_policies.append({key: tags[key] for key in ("p", "sp", "pct") if key in tags})
            if tags.get("p") == "none":
                dmarc["issues"].append(_issue("DMARC_MONITOR_ONLY", "DMARC usa p=none y solo monitoriza suplantación.", evaluable=True, severity="media", rule="CONF-003"))
            if tags.get("p") not in {"none", "quarantine", "reject"}:
                dmarc["issues"].append(_issue("DMARC_POLICY_INVALID", "DMARC no contiene una política p válida.", evaluable=True, severity="media", rule="CONF-003"))
            try:
                if "pct" in tags:
                    percentage = int(tags["pct"])
                    if not 0 <= percentage <= 100:
                        raise ValueError
                    if percentage < 100:
                        dmarc["issues"].append(_issue("DMARC_PARTIAL_PERCENTAGE", "DMARC se aplica a menos del 100 % de los mensajes.", evaluable=True, severity="baja", rule="CONF-003"))
            except ValueError:
                dmarc["issues"].append(_issue("DMARC_PCT_INVALID", "DMARC contiene un valor pct inválido.", evaluable=True, severity="media", rule="CONF-003"))
        dmarc["policies"] = parsed_policies

    checks.append({"check": "dkim", "name": f"<selector>._domainkey.{target}", "rrtype": "TXT", "state": "unverified",
                   "records": [], "dnssec_validated": None, "rcode": None, "checked_at": checks[0]["checked_at"], "query": "",
                   "issues": [], "interpretation": "DKIM no puede enumerarse de forma fiable sin conocer un selector; no se declara ausente ni inseguro."})

    cname = by_id["cname"]
    if cname["state"] == "present":
        cname["interpretation"] = "El nombre es un alias. El destino se conserva como evidencia DNS, pero no se atribuye como activo del cliente."
        for key in ("a", "aaaa"):
            if by_id[key]["state"] == "absent":
                by_id[key].update(state="not_applicable", interpretation="El nombre usa CNAME; la ausencia de este tipo exacto no es una falla.")
    caa = by_id["caa"]
    if caa["state"] == "absent":
        caa["interpretation"] = "No se encontró CAA exacto. Es una medida opcional y su ausencia no genera un hallazgo."
    for check_id in ("mta_sts", "tls_rpt"):
        check = by_id[check_id]
        if check["state"] == "absent":
            check["interpretation"] = ("No se encontró el registro exacto. Se informa como mejora potencial, no como hallazgo puntuable."
                                       if mail_enabled else "No se encontró el registro y el activo no publica recepción de correo; no aplica como riesgo.")

    conclusive = [check for check in checks if check["check"] not in {"dnssec", "dkim"} and check["state"] not in {"error", "unverified"}]
    if any(check.get("dnssec_validated") for check in conclusive):
        dnssec_state, dnssec_text = "present", "Google Public DNS validó criptográficamente al menos una respuesta exacta (AD=true)."
    elif by_id["ds"]["state"] == "present":
        dnssec_state, dnssec_text = "present", "Se encontró un registro DS exacto de delegación; la cadena no se afirma validada si AD no fue verdadero."
    else:
        dnssec_state, dnssec_text = "unverified", "No hubo validación AD ni un DS exacto suficiente; esto no prueba que DNSSEC esté mal configurado."
    checks.append({"check": "dnssec", "name": target, "rrtype": "DS/AD", "state": dnssec_state,
                   "records": by_id["ds"]["records"], "dnssec_validated": dnssec_state == "present" and any(check.get("dnssec_validated") for check in conclusive),
                   "rcode": by_id["ds"]["rcode"], "checked_at": checks[0]["checked_at"], "query": by_id["ds"]["query"],
                   "issues": [], "interpretation": dnssec_text})


def _dns_assess_cname_target(fetch, report, checks):
    """Conservatively identify a dangling CNAME without testing claimability."""
    cname = next(check for check in checks if check["check"] == "cname")
    targets = sorted({_dns_name(record.get("data")) for record in cname["records"]
                      if _dns_name(record.get("data"))})
    if not targets:
        return
    if len(targets) != 1:
        cname["cname_target_assessment"] = {
            "target": None, "state": "unverified", "checked_at": report["checked_at"],
            "passive": True, "claimability_verified": False, "attributed_to_customer": False,
            "queries": [],
            "interpretation": "Múltiples destinos CNAME impiden evaluar pasivamente una referencia colgante.",
        }
        return

    target = targets[0]
    probes = [_dns_query(fetch, report, f"cname_target_{rrtype.lower()}", rrtype, target)
              for rrtype in ("A", "AAAA")]
    rcodes = [probe.get("rcode") for probe in probes]
    if rcodes == [3, 3]:
        state = "nxdomain"
        interpretation = ("El destino CNAME devolvió NXDOMAIN para A y AAAA mediante Google Public DNS. "
                          "Es una referencia potencialmente colgante, pero no demuestra que el recurso sea reclamable.")
        cname["issues"].append(_issue(
            "DANGLING_CNAME_NXDOMAIN", interpretation,
            evaluable=False, severity="informativa", rule="INFRA-004",
        ))
    elif rcodes == [0, 0]:
        if any(probe["records"] for probe in probes):
            state = "resolvable"
            interpretation = "El destino CNAME conserva resolución DNS pública; no hay evidencia pasiva de referencia colgante."
        else:
            state = "exists_without_address"
            interpretation = ("El destino CNAME respondió NOERROR sin direcciones exactas. "
                              "No se interpreta como recurso inexistente ni como takeover.")
    else:
        state = "unverified"
        interpretation = "Las respuestas del destino CNAME fueron incompletas o inconsistentes; INFRA-004 no puede evaluarse."
    cname["cname_target_assessment"] = {
        "target": target, "state": state, "checked_at": report["checked_at"],
        "passive": True, "claimability_verified": False, "attributed_to_customer": False,
        "queries": [{"rrtype": probe["rrtype"], "state": probe["state"],
                     "rcode": probe["rcode"], "http_status": probe.get("http_status"),
                     "query": probe["query"]} for probe in probes],
        "interpretation": interpretation,
    }


def _dns_doh(fetch, report):
    target = _dns_name(report["target"])
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", target):
        raise ValueError("Nombre de dominio inválido")
    checks = []
    consecutive_provider_failures = 0
    for check_id, rrtype, prefix in DNS_QUERIES:
        name = target if prefix == "target" else f"{prefix}.{target}"
        skip_reason = (
            "se alcanzó el límite de dos fallos consecutivos"
            if consecutive_provider_failures >= 2 else None
        )
        check = _dns_query(fetch, report, check_id, rrtype, name, skip_reason=skip_reason)
        checks.append(check)
        if skip_reason:
            continue
        consecutive_provider_failures = (
            consecutive_provider_failures + 1 if check["state"] == "error" else 0
        )
    _dns_interpret(checks, target)
    _dns_assess_cname_target(fetch, report, checks)
    report["checks"] = checks
    report["queries"] = [check["query"] for check in checks if check["query"]]
    cname_assessment = next(check for check in checks if check["check"] == "cname").get("cname_target_assessment")
    if cname_assessment:
        report["queries"].extend(query["query"] for query in cname_assessment["queries"])
    report["query"] = "Google Public DNS DoH: consultas exactas A, AAAA, CNAME, MX, TXT, CAA, NS, SOA, DS, DMARC, MTA-STS y TLS-RPT"
    report["limitations"] = [
        "Datos de un resolvedor recursivo y sus cachés; no se consulta directamente al activo ni a sus servidores autoritativos.",
        "DKIM no se declara ausente porque sus selectores no pueden enumerarse de forma fiable.",
        "Solo se atribuyen registros cuyo propietario coincide exactamente con el nombre consultado; destinos de proveedores no se convierten en activos.",
        "La ausencia de DMARC exacto no se puntúa sin verificar la política heredada del dominio organizacional.",
        "Un destino CNAME con NXDOMAIN se informa como referencia potencialmente colgante; sin prueba de reclamabilidad no activa INFRA-004.",
    ]
    report["results"] = sum(len(check["records"]) for check in checks if check["check"] not in {"spf", "dnssec"})
    failed = sum(check["state"] == "error" for check in checks if check["check"] not in {"spf", "dnssec", "dkim"})
    queried = len(DNS_QUERIES)
    if failed == queried:
        error_types = sorted({str(check.get("error_type")) for check in checks
                              if check.get("error_type") and check.get("error_type") != "provider_circuit_open"})
        detail = f" ({', '.join(error_types)})" if error_types else ""
        report.update(status="error", error=(
            "Fallaron todas las consultas DNS DoH; el activo no fue evaluado" + detail
        ))
    elif failed:
        report.update(status="partial", error=f"{failed} de {queried} consultas DNS no pudieron verificarse")
    else:
        report["status"] = "ok"
    for check in checks:
        _dns_check_event(report, check)


def _event(report, kind, value, origin=None, observed_at=None, **metadata):
    report["events"].append({"event_type": kind, "data": value,
        "source_data": origin or report["target"], "observed_at": observed_at,
        "metadata": {"proveedor": report["provider"], "consulta": report["query"],
                     "consultado_en": report["checked_at"], "observado_por_proveedor_en": observed_at,
                     "pasivo": True, **metadata}})


def _dns_check_event(report, check):
    _event(report, "DNS_POSTURE", f"{check['check']}:{check['state']}",
           check=check["check"], estado=check["state"], nombre_consultado=check["name"],
           rrtype=check["rrtype"], registros=check["records"], rcode=check["rcode"],
           dnssec_validated=check["dnssec_validated"], interpretacion=check["interpretation"],
           issues=check["issues"], politicas_dmarc=check.get("policies", []),
           evaluacion_destino_cname=check.get("cname_target_assessment"))


def _urlscan(data, report, *, fetch=None, detail_limit=3, headers_max_age_days=90):
    if not 0 <= detail_limit <= 5 or not 1 <= headers_max_age_days <= 365:
        raise ValueError("Límites de detalle urlscan inválidos")
    rows = data.get("results")
    if not isinstance(rows, list):
        raise ValueError("Falta results")
    history_limit = data.get("search_date_limit_days")
    report["search_date_limit_days"] = history_limit if type(history_limit) is int else None
    report["limitations"] = [
        "Una consulta Search API por activo, hasta 100 resultados; no se solicitaron nuevos escaneos.",
        "La evidencia es histórica: tecnologías, TLS y banners no prueban el estado actual ni una vulnerabilidad.",
    ]
    report["header_evaluation"] = {
        "status": "not_available" if fetch is None or detail_limit == 0 else "pending",
        "requested": 0, "complete": 0, "unverifiable": 0,
        "max_results": detail_limit, "max_age_days": headers_max_age_days,
    }
    report["redirect_evaluation"] = {
        "status": "not_available" if fetch is None or detail_limit == 0 else "pending",
        "requested": 0, "complete": 0, "unverifiable": 0,
        "max_results": detail_limit, "max_age_days": headers_max_age_days,
    }
    if fetch is None:
        report["limitations"].append(
            "Las cabeceras HTTP no se evaluaron: Result API requiere una API key; Search API no prueba su ausencia."
        )
    elif detail_limit == 0:
        report["limitations"].append("La consulta de detalle de cabeceras HTTP está deshabilitada.")
    if type(history_limit) is int:
        report["limitations"].append(f"El proveedor limitó esta cuenta o consulta a {history_limit} días de historial.")
    groups = {}
    skipped = 0
    detail_candidates = []
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        page = row.get("page") if isinstance(row.get("page"), dict) else {}
        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        page_domain = _dns_name(page.get("domain"))
        task_domain = _dns_name(task.get("domain"))
        if not task_domain and isinstance(task.get("url"), str):
            try:
                task_domain = _dns_name(urlsplit(task["url"]).hostname)
            except ValueError:
                task_domain = ""
        target = _dns_name(report["target"])
        page_exact, task_exact = page_domain == target, task_domain == target
        if not (page_exact or task_exact):
            continue
        report["results"] += 1
        when = task.get("time") if isinstance(task.get("time"), str) else None
        reference = row.get("_id") or task.get("uuid")
        evidence = {"fecha": when, "referencia": reference}
        _urlscan_group(groups, "URLSCAN_HISTORY", report["target"], evidence)
        if page_exact and isinstance(reference, str) and reference.strip():
            detail_candidates.append((when or "", reference.strip(), page.get("url")))

        redirected = page.get("redirected")
        final_url, task_url = page.get("url"), task.get("url")
        if redirected or (task_exact and page_domain and not page_exact):
            value = str(redirected or "off-domain")
            _urlscan_group(groups, "URLSCAN_REDIRECT", value, evidence,
                           url_inicial=task_url, url_final=final_url,
                           dominio_final=page_domain, evaluable=False,
                           reglas_candidatas=["CONF-008"])
        if not page_exact:
            continue
        if isinstance(page.get("server"), str) and page["server"].strip():
            _urlscan_group(groups, "WEBSERVER_BANNER", page["server"].strip(), evidence,
                           evaluable=False, reglas_candidatas=["INFRA-003"])
        content = row.get("content") if isinstance(row.get("content"), dict) else {}
        technologies = content.get("technologies") if isinstance(content.get("technologies"), list) else []
        for technology in technologies:
            if isinstance(technology, str) and technology.strip():
                _urlscan_group(groups, "WEBSERVER_TECHNOLOGY", technology.strip(), evidence,
                               evaluable=False, reglas_candidatas=["INFRA-003"])
        if isinstance(page.get("status"), (str, int)) and not isinstance(page.get("status"), bool):
            _urlscan_group(groups, "URLSCAN_HTTP_STATUS", str(page["status"]), evidence, evaluable=False)
        tls = {key: page[key] for key in ("tlsIssuer", "tlsValidFrom", "tlsValidDays", "tlsAgeDays")
               if isinstance(page.get(key), (str, int)) and not isinstance(page.get(key), bool)}
        if tls:
            tls_evidence = _urlscan_tls_evidence(
                tls, final_url, when, report["checked_at"], report["target"]
            )
            _urlscan_group(groups, "URLSCAN_TLS_CERTIFICATE", json.dumps(tls, sort_keys=True, ensure_ascii=False), evidence,
                           **tls_evidence)
        metadata = {key: page[key] for key in ("ip", "asn", "asnname", "country", "mimeType", "title")
                    if isinstance(page.get(key), (str, int)) and not isinstance(page.get(key), bool)}
        if metadata:
            _urlscan_group(groups, "URLSCAN_PAGE_METADATA", json.dumps(metadata, sort_keys=True, ensure_ascii=False), evidence,
                           evaluable=False)
        verdicts = row.get("verdicts") if isinstance(row.get("verdicts"), dict) else {}
        urlscan_verdict = verdicts.get("urlscan") if isinstance(verdicts.get("urlscan"), dict) else {}
        score = urlscan_verdict.get("score")
        if type(score) in {int, float} and score > 0:
            verdict = {"score": score, "categories": urlscan_verdict.get("categories", [])}
            _urlscan_group(groups, "URLSCAN_VERDICT", json.dumps(verdict, sort_keys=True, ensure_ascii=False), evidence,
                           evaluable=False, posible_riesgo=True)
    if fetch is not None and detail_limit:
        seen = set()
        selected = []
        for when, reference, page_url in sorted(detail_candidates, reverse=True):
            if reference in seen:
                continue
            seen.add(reference)
            selected.append((when, reference, page_url))
            if len(selected) == detail_limit:
                break
        for when, reference, page_url in selected:
            report["header_evaluation"]["requested"] += 1
            report["redirect_evaluation"]["requested"] += 1
            try:
                code, detail = fetch(f"https://urlscan.io/api/v1/result/{quote(reference, safe='')}/", {})
            except Exception:
                code, detail = None, None
            event = _urlscan_security_headers(
                detail, report["target"], page_url, when, reference,
                report["checked_at"], headers_max_age_days,
            ) if code == 200 else None
            if event is None:
                report["header_evaluation"]["unverifiable"] += 1
            else:
                report["header_evaluation"]["complete"] += 1
                _urlscan_group(groups, "URLSCAN_SECURITY_HEADERS", event.pop("data"),
                               {"fecha": when, "referencia": event.pop("referencia")}, **event)
            redirect_event = _urlscan_http_redirect(
                detail, report["target"], when, reference,
                report["checked_at"], headers_max_age_days,
            ) if code == 200 else None
            if redirect_event is None:
                report["redirect_evaluation"]["unverifiable"] += 1
            else:
                report["redirect_evaluation"]["complete"] += 1
                _urlscan_group(groups, "URLSCAN_HTTP_REDIRECT", redirect_event.pop("data"),
                               {"fecha": when, "referencia": redirect_event.pop("referencia")},
                               **redirect_event)
        for evaluation in (report["header_evaluation"], report["redirect_evaluation"]):
            complete = evaluation["complete"]
            requested = evaluation["requested"]
            evaluation["status"] = (
                "complete" if requested and complete == requested else "partial" if complete else "unverifiable"
            )
        if report["header_evaluation"]["unverifiable"]:
            report["limitations"].append(
                "Algunos detalles de Result API faltaron o tuvieron un formato incompleto; no se interpretaron como cabeceras ausentes."
            )
        if report["redirect_evaluation"]["unverifiable"]:
            report["limitations"].append(
                "Algunas cadenas de redirección faltaron o estuvieron incompletas; no se interpretaron como ausencia de HTTPS."
            )
    for group in groups.values():
        timeline = group.pop("timeline")
        dates = sorted({item["fecha"] for item in timeline if item.get("fecha")})
        references = list(dict.fromkeys(item["referencia"] for item in timeline if item.get("referencia")))
        _event(report, group.pop("event_type"), group.pop("data"), observed_at=dates[-1] if dates else None,
               ocurrencias=len(timeline), primera_observacion=dates[0] if dates else None,
               ultima_observacion=dates[-1] if dates else None, fechas=dates,
               referencias=references, historico=True, **group)
    if skipped:
        report["status"] = "partial"
        report["error"] = f"{skipped} resultados no tuvieron el formato esperado"
        report["limitations"].append("Se omitieron resultados incompletos sin atribuirlos al activo.")
    total = data.get("total", len(rows))
    if data.get("has_more") or (isinstance(total, int) and total > len(rows)) or len(rows) >= 100:
        report.update(status="partial", error="Se alcanzó el límite de resultados; el historial no está completo")


def _urlscan_group(groups, event_type, value, evidence, **metadata):
    key = (event_type, value, json.dumps(metadata, sort_keys=True, default=str))
    group = groups.setdefault(key, {"event_type": event_type, "data": value, "timeline": [], **metadata})
    group["timeline"].append(evidence)


def _urlscan_tls_evidence(tls, page_url, observed_at, checked_at, target):
    base = {"evaluable": False, "evidencia_completa": False,
            "verificado_actual": False, "potencial": False, "issues": [],
            "reglas_candidatas": []}
    try:
        parsed_url = urlsplit(page_url or "")
    except ValueError:
        return base
    if parsed_url.scheme.lower() != "https" or _dns_name(parsed_url.hostname) != _dns_name(target):
        return base
    valid_from = _parse_datetime(tls.get("tlsValidFrom"))
    observed = _parse_datetime(observed_at)
    checked = _parse_datetime(checked_at)
    try:
        valid_days = int(tls.get("tlsValidDays"))
    except (TypeError, ValueError):
        return base
    if valid_from is None or observed is None or checked is None or not 1 <= valid_days <= 825:
        return base
    expires = valid_from + timedelta(days=valid_days)
    if observed > checked + timedelta(minutes=5) or not valid_from <= observed < expires:
        return base
    scan_age_days = max(0, (checked - observed).days)
    reported_age = tls.get("tlsAgeDays")
    coherent = True
    if reported_age is not None:
        try:
            coherent = abs(int(reported_age) - max(0, (observed - valid_from).days)) <= 2
        except (TypeError, ValueError):
            coherent = False
    seconds_remaining = (expires - checked).total_seconds()
    expiring = coherent and scan_age_days <= 7 and 0 < seconds_remaining <= 14 * 86400
    issue = _issue(
        "TLS_CERTIFICATE_EXPIRING_HISTORICAL",
        "Un certificado servido en una visita histórica reciente de urlscan vencería en 14 días o menos; requiere confirmar el certificado actual.",
        evaluable=expiring, severity="baja", rule="CONF-007",
    ) if expiring else None
    return {
        **base, "evidencia_completa": coherent, "evaluable": expiring,
        "potencial": expiring, "issues": [issue] if issue else [],
        "reglas_candidatas": ["CONF-007"] if issue else [],
        "valido_desde": valid_from.isoformat(), "valido_hasta": expires.isoformat(),
        "dias_restantes": round(seconds_remaining / 86400, 1),
        "antiguedad_evidencia_dias": scan_age_days,
        "emisor": tls.get("tlsIssuer"),
    }


def _urlscan_security_headers(detail, target, expected_url, observed_at, reference,
                              checked_at, max_age_days):
    """Interpret one complete primary HTML response; missing API fields never imply absent headers."""
    if not isinstance(detail, dict):
        return None
    page = detail.get("page") if isinstance(detail.get("page"), dict) else {}
    primary_url = page.get("url") if isinstance(page.get("url"), str) else expected_url
    try:
        parsed = urlsplit(primary_url or "")
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or _dns_name(parsed.hostname) != _dns_name(target):
        return None
    status = page.get("status")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    mime = str(page.get("mimeType") or "").split(";", 1)[0].strip().lower()
    requests = (detail.get("data") or {}).get("requests") if isinstance(detail.get("data"), dict) else None
    if not isinstance(requests, list):
        return None
    response = None
    for transaction in requests:
        if not isinstance(transaction, dict):
            continue
        wrapper = transaction.get("response")
        candidates = []
        if isinstance(wrapper, dict):
            candidates.extend([wrapper.get("response"), wrapper])
        for candidate in candidates:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("url"), str):
                continue
            try:
                candidate_url = urlsplit(candidate["url"])
            except ValueError:
                continue
            if (_dns_name(candidate_url.hostname) == _dns_name(target)
                    and candidate_url._replace(fragment="").geturl() == parsed._replace(fragment="").geturl()):
                response = candidate
                break
        if response is not None:
            break
    if response is None or "headers" not in response or not isinstance(response.get("headers"), dict):
        return None
    headers = {str(key).strip().lower(): str(value) for key, value in response["headers"].items()
               if isinstance(key, str)}
    if not headers:
        return None
    if status is None:
        try:
            status = int(response.get("status"))
        except (TypeError, ValueError):
            return None
    if not mime:
        mime = str(response.get("mimeType") or "").split(";", 1)[0].strip().lower()
    applicable = status is not None and 200 <= status < 300 and mime in {"text/html", "application/xhtml+xml"}
    observed = _parse_datetime(observed_at)
    checked = _parse_datetime(checked_at)
    age_days = max(0, (checked - observed).days) if observed and checked else None
    recent = age_days is not None and age_days <= max_age_days
    evaluable = applicable and recent
    csp = headers.get("content-security-policy", "")
    checks = {
        "strict-transport-security": "strict-transport-security" in headers,
        "content-security-policy": "content-security-policy" in headers,
        "x-content-type-options": "x-content-type-options" in headers,
        "clickjacking-protection": "x-frame-options" in headers or "frame-ancestors" in csp.lower(),
        "referrer-policy": "referrer-policy" in headers,
        "permissions-policy": "permissions-policy" in headers,
    }
    messages = {
        "strict-transport-security": "La respuesta HTTPS histórica no incluyó HSTS.",
        "content-security-policy": "La respuesta HTML histórica no incluyó Content-Security-Policy.",
        "x-content-type-options": "La respuesta HTML histórica no incluyó X-Content-Type-Options.",
        "clickjacking-protection": "La respuesta HTML histórica no incluyó X-Frame-Options ni CSP frame-ancestors.",
    }
    issues = [_issue("HTTP_HEADER_" + name.upper().replace("-", "_"), message,
                     evaluable=evaluable, severity="baja", rule="CONF-004")
              for name, message in messages.items() if not checks[name]]
    return {
        "data": json.dumps({"presentes": sorted(name for name, present in checks.items() if present),
                            "ausentes": sorted(name for name, present in checks.items() if not present)},
                           sort_keys=True, ensure_ascii=False),
        "referencia": f"https://urlscan.io/result/{reference}/",
        "url": primary_url, "estado_http": status, "tipo_mime": mime,
        "cabeceras_completas": True, "cabeceras": checks, "issues": issues,
        "evaluable": evaluable, "verificado_actual": False,
        "potencial": bool(issues), "antiguedad_dias": age_days,
        "reglas_candidatas": ["CONF-004"] if issues else [],
    }


def _urlscan_http_redirect(detail, target, observed_at, reference, checked_at, max_age_days):
    """Interpret only an explicit Result API redirect chain for the exact hostname."""
    if not isinstance(detail, dict):
        return None
    task = detail.get("task") if isinstance(detail.get("task"), dict) else {}
    page = detail.get("page") if isinstance(detail.get("page"), dict) else {}
    data = detail.get("data") if isinstance(detail.get("data"), dict) else {}
    initial_url, final_url = task.get("url"), page.get("url")
    redirects = data.get("redirects")
    if not isinstance(initial_url, str) or not isinstance(final_url, str) or not isinstance(redirects, list):
        return None
    try:
        initial, final = urlsplit(initial_url), urlsplit(final_url)
    except ValueError:
        return None
    exact = _dns_name(target)
    if (_dns_name(initial.hostname) != exact or _dns_name(final.hostname) != exact
            or initial.scheme.lower() not in {"http", "https"}
            or final.scheme.lower() not in {"http", "https"}):
        return None
    chain_urls = []
    for step in redirects:
        if not isinstance(step, dict):
            return None
        urls = [value for key in ("url", "from", "to", "source", "target", "location")
                if isinstance((value := step.get(key)), str) and value.startswith(("http://", "https://"))]
        if not urls:
            return None
        for value in urls:
            try:
                if _dns_name(urlsplit(value).hostname) != exact:
                    return None
            except ValueError:
                return None
            if value not in chain_urls:
                chain_urls.append(value)
    try:
        status = int(page.get("status"))
    except (TypeError, ValueError):
        return None
    mime = str(page.get("mimeType") or "").split(";", 1)[0].strip().lower()
    applicable_response = 200 <= status < 300 and mime in {"text/html", "application/xhtml+xml"}
    observed = _parse_datetime(observed_at)
    checked = _parse_datetime(checked_at)
    age_days = max(0, (checked - observed).days) if observed and checked else None
    recent = age_days is not None and age_days <= max_age_days
    if initial.scheme.lower() == "https":
        state = "https_directo"
    elif final.scheme.lower() == "https" and redirects:
        state = "redirige_a_https"
    elif final.scheme.lower() == "http" and applicable_response:
        state = "http_sin_redireccion_https"
    else:
        return None
    evaluable = state == "http_sin_redireccion_https" and recent
    issues = []
    if state == "http_sin_redireccion_https":
        issues.append(_issue(
            "HTTP_WITHOUT_HTTPS_REDIRECT",
            "La navegación HTTP histórica terminó en una respuesta HTML 2xx del mismo hostname sin migrar a HTTPS.",
            evaluable=evaluable, severity="media", rule="CONF-008",
        ))
    return {
        "data": state, "referencia": f"https://urlscan.io/result/{reference}/",
        "estado": state, "url_inicial": initial_url, "url_final": final_url,
        "estado_http": status, "tipo_mime": mime, "cadena_redireccion": chain_urls,
        "cadena_completa": True, "evidencia_explicita": True, "issues": issues,
        "evaluable": evaluable, "verificado_actual": False,
        "potencial": bool(issues), "antiguedad_dias": age_days,
        "reglas_candidatas": ["CONF-008"] if issues else [],
    }


def _parse_datetime(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _commoncrawl(fetch, report, index_count, max_results, deadline_seconds, retry_delay_seconds):
    if (not 1 <= index_count <= 3 or not 1 <= max_results <= 100
            or not 0.01 <= deadline_seconds <= 60 or not 0 <= retry_delay_seconds <= 2):
        raise ValueError("Límites Common Crawl inválidos")
    deadline_at = time.monotonic() + deadline_seconds
    catalog_url = "https://index.commoncrawl.org/collinfo.json"
    report["query"] = (f"{catalog_url}; hostname exacto; {index_count} índices recientes; "
                       f"máximo {max_results} capturas por índice")
    report["limitations"] = [
        "Solo se consultó el índice público; no se descargaron WARC ni se contactó al activo.",
        f"Cobertura limitada a los {index_count} índices más recientes y {max_results} capturas por índice.",
        "Las capturas son históricas y no prueban que una URL o respuesta siga expuesta actualmente.",
        "Un nombre sensible en una URL es una señal informativa; no confirma filtración ni activa FUGA-002.",
    ]
    report["queries"] = []
    report["max_concurrency"] = 2
    report["deadline_seconds"] = deadline_seconds
    try:
        code, collections, catalog_attempts = _commoncrawl_fetch(
            fetch, catalog_url, {}, deadline_at, retry_delay_seconds,
        )
    except Exception:
        report["error"] = "No fue posible consultar el catálogo antes del plazo global"
        return
    report["catalog_http_status"] = code
    report["catalog_attempts"] = catalog_attempts
    if code != 200 or not isinstance(collections, list):
        report["error"] = f"No fue posible consultar el catálogo de índices (HTTP {code})"
        return
    selected = []
    for item in collections:
        if not isinstance(item, dict):
            continue
        identifier, endpoint = item.get("id"), item.get("cdx-api")
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        if (not isinstance(identifier, str) or not re.fullmatch(r"CC-MAIN-\d{4}-\d{2}", identifier)
                or not parsed or parsed.scheme != "https" or parsed.hostname != "index.commoncrawl.org"
                or not parsed.path.endswith("-index")):
            continue
        selected.append({"id": identifier, "endpoint": endpoint,
                         "from": item.get("from"), "to": item.get("to")})
        if len(selected) == index_count:
            break
    if not selected:
        report["error"] = "El catálogo no incluyó índices Common Crawl válidos"
        return
    report["indexes"] = [{key: item.get(key) for key in ("id", "from", "to")} for item in selected]
    groups = {}
    successful = failed = malformed = foreign = 0
    truncated = False
    jobs = []
    for collection in selected:
        params = {"url": _dns_name(report["target"]), "matchType": "host", "output": "json",
                  "limit": max_results,
                  "fl": "url,timestamp,status,mime,mime-detected,digest,filename,offset,length"}
        query_url = collection["endpoint"] + "?" + urlencode(params)
        query = {"index": collection["id"], "from": collection.get("from"), "to": collection.get("to"),
                 "query": query_url, "status": "error", "results": 0}
        report["queries"].append(query)
        jobs.append((collection, params, query))

    executor = ThreadPoolExecutor(max_workers=min(2, len(jobs)), thread_name_prefix="commoncrawl")
    futures = {
        executor.submit(
            _commoncrawl_fetch, fetch, collection["endpoint"], params,
            deadline_at, retry_delay_seconds,
        ): (collection, params, query)
        for collection, params, query in jobs
    }
    remaining = max(0.0, deadline_at - time.monotonic())
    done, pending = wait(futures, timeout=remaining)
    for future in pending:
        future.cancel()
    executor.shutdown(wait=False, cancel_futures=True)

    for future, (collection, _params, query) in futures.items():
        if future not in done:
            query["error"] = "Se agotó el plazo global de Common Crawl"
            failed += 1
            continue
        try:
            query_code, rows, attempts = future.result()
        except Exception:
            query["error"] = "No fue posible consultar este índice antes del plazo global"
            failed += 1
            continue
        query["attempts"] = attempts
        query["http_status"] = query_code
        valid_empty = query_code == 404 and rows == []
        if (query_code != 200 and not valid_empty) or not isinstance(rows, list):
            query["error"] = f"Índice respondió HTTP {query_code} o un formato inválido"
            failed += 1
            continue
        successful += 1
        query["status"] = "empty" if valid_empty else "ok"
        query["results"] = len(rows)
        query["truncated"] = len(rows) >= max_results
        truncated = truncated or query["truncated"]
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("url"), str):
                malformed += 1
                continue
            try:
                parsed_url = urlsplit(row["url"])
            except ValueError:
                malformed += 1
                continue
            if _dns_name(parsed_url.hostname) != _dns_name(report["target"]):
                foreign += 1
                continue
            if parsed_url.scheme not in {"http", "https"} or len(row["url"]) > 2048:
                malformed += 1
                continue
            timestamp = row.get("timestamp") if isinstance(row.get("timestamp"), str) else ""
            observed_at = _commoncrawl_time(timestamp)
            if not observed_at:
                malformed += 1
                continue
            report["results"] += 1
            mime = _commoncrawl_field(row.get("mime-detected") or row.get("mime"))
            status = _commoncrawl_field(row.get("status"))
            reference_params = {"url": row["url"], "matchType": "exact", "output": "json",
                                "from": timestamp, "to": timestamp, "limit": 1}
            evidence = {
                "fecha": observed_at,
                "indice": collection["id"],
                "estado_http": status,
                "mime": mime,
                "digest": _commoncrawl_field(row.get("digest")),
                "referencia": collection["endpoint"] + "?" + urlencode(reference_params),
                "warc": {key: row.get(key) for key in ("filename", "offset", "length")
                         if isinstance(row.get(key), str)},
            }
            document = _commoncrawl_document_details(parsed_url, mime)
            signals = _commoncrawl_sensitive_signals(parsed_url)
            possible_sensitive_document = document["is_document"] and bool(signals)
            issues = ([ _issue(
                "POTENTIAL_SENSITIVE_DOCUMENT_NAME",
                "El nombre de un documento indexado contiene términos potencialmente sensibles; no confirma su contenido ni una filtración.",
                evaluable=False, severity="informativa", rule="FUGA-002",
            )] if possible_sensitive_document else [])
            metadata = {
                "categoria": _commoncrawl_category(parsed_url, mime),
                "hostname_exacto": _dns_name(parsed_url.hostname),
                "url": row["url"],
                "documento_indexado": document["is_document"],
                "extension_documento": document["extension"],
                "tipo_documento": document["kind"],
                "historico": True,
                "evaluable": False,
                "verificado": False,
                "verificado_actual": False,
                "posible_exposicion_por_nombre": bool(signals),
                "posible_documento_sensible": possible_sensitive_document,
                "senales_nombre": signals,
                "issues": issues,
                "reglas_candidatas": ["FUGA-002"] if possible_sensitive_document else [],
                "interpretacion": (
                    "El nombre del documento contiene términos potencialmente sensibles, pero el índice no confirma su contenido ni una filtración."
                    if possible_sensitive_document else
                    "La ruta contiene términos potencialmente sensibles, pero no corresponde a evidencia documental ni confirma una filtración."
                    if signals else
                    "Documento histórico indexado; no hay evidencia suficiente de contenido sensible."
                    if document["is_document"] else
                    "URL histórica indexada; no confirma exposición actual."
                ),
            }
            _commoncrawl_group(groups, row["url"], evidence, metadata)
    for group in groups.values():
        timeline = group.pop("timeline")
        dates = sorted({item["fecha"] for item in timeline})
        references = list(dict.fromkeys(item["referencia"] for item in timeline))
        statuses = sorted({item["estado_http"] for item in timeline if item["estado_http"]})
        mimes = sorted({item["mime"] for item in timeline if item["mime"]})
        indexes = list(dict.fromkeys(item["indice"] for item in timeline))
        records = [{"fecha": item["fecha"], "indice": item["indice"], "digest": item["digest"],
                    "warc": item["warc"], "referencia": item["referencia"]} for item in timeline[:10]]
        _event(report, "COMMONCRAWL_URL", group.pop("data"), observed_at=dates[-1],
               ocurrencias=len(timeline), primera_observacion=dates[0], ultima_observacion=dates[-1],
               fechas=dates, estados_http=statuses, tipos_mime=mimes, indices=indexes,
               referencias=references[:10], registros_indice=records, **group)
    report["unique_urls"] = len(groups)
    problems = []
    if failed:
        problems.append(f"{failed} índices no pudieron consultarse")
    if malformed:
        problems.append(f"{malformed} filas inválidas se descartaron")
    if foreign:
        problems.append(f"{foreign} filas de otros hostnames se descartaron")
    if truncated:
        problems.append("se alcanzó el límite de capturas en al menos un índice")
    if successful == 0:
        report["error"] = "; ".join(problems) or "No se pudo consultar ningún índice"
    elif problems:
        report.update(status="partial", error="; ".join(problems))
    else:
        report["status"] = "ok" if report["results"] else "empty"


def _commoncrawl_fetch(fetch, url, params, deadline_at, retry_delay_seconds):
    """Reintenta una vez fallos transitorios, respetando el plazo compartido."""
    last = None
    for attempt in range(1, 3):
        if time.monotonic() >= deadline_at:
            raise TimeoutError("Se agotó el plazo global de Common Crawl")
        try:
            last = fetch(url, params)
        except Exception:
            if attempt == 2:
                raise
            _commoncrawl_retry_pause(deadline_at, retry_delay_seconds)
            continue
        status = last[0]
        if status != 429 and not (isinstance(status, int) and 500 <= status <= 599):
            return last[0], last[1], attempt
        if attempt < 2:
            _commoncrawl_retry_pause(deadline_at, retry_delay_seconds)
    return last[0], last[1], 2


def _commoncrawl_retry_pause(deadline_at, retry_delay_seconds):
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Se agotó el plazo global de Common Crawl")
    if retry_delay_seconds:
        time.sleep(min(retry_delay_seconds, remaining))


def _commoncrawl_group(groups, url, evidence, metadata):
    group = groups.setdefault(url, {"data": url, "timeline": [], **metadata})
    group["timeline"].append(evidence)


def _commoncrawl_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{14}", value):
        return None
    try:
        return datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def _commoncrawl_field(value):
    return str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip() not in {"", "-"} else None


def _commoncrawl_document_details(parsed_url, mime):
    path = parsed_url.path.lower()
    extensions = {
        ".pdf": "PDF", ".doc": "Word", ".docx": "Word", ".rtf": "RTF",
        ".xls": "Excel", ".xlsx": "Excel", ".csv": "CSV",
        ".ppt": "PowerPoint", ".pptx": "PowerPoint",
        ".odt": "OpenDocument", ".ods": "OpenDocument", ".odp": "OpenDocument",
        ".txt": "texto",
    }
    mime_kinds = {
        "application/pdf": "PDF",
        "application/msword": "Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word",
        "application/vnd.ms-excel": "Excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel",
        "application/vnd.ms-powerpoint": "PowerPoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint",
        "application/rtf": "RTF", "text/rtf": "RTF", "text/csv": "CSV", "text/plain": "texto",
        "application/vnd.oasis.opendocument.text": "OpenDocument",
        "application/vnd.oasis.opendocument.spreadsheet": "OpenDocument",
        "application/vnd.oasis.opendocument.presentation": "OpenDocument",
    }
    extension = next((suffix for suffix in sorted(extensions, key=len, reverse=True) if path.endswith(suffix)), None)
    normalized_mime = str(mime or "").split(";", 1)[0].strip().lower()
    kind = extensions.get(extension) or mime_kinds.get(normalized_mime)
    return {"is_document": kind is not None, "extension": extension, "kind": kind}


def _commoncrawl_category(parsed_url, mime):
    path = parsed_url.path.lower()
    if _commoncrawl_document_details(parsed_url, mime)["is_document"]:
        return "documento"
    if path.endswith((".zip", ".tar", ".gz", ".sql")) or mime == "application/zip":
        return "archivo"
    if any(token in path for token in ("/api/", "/graphql", "/swagger", "/openapi", "/.well-known/")) or path.endswith((".json", ".xml")):
        return "endpoint"
    return "url"


def _commoncrawl_sensitive_signals(parsed_url):
    # Query parameters are excluded: names such as ?config=public commonly
    # describe application behavior and are not evidence about file contents.
    value = parsed_url.path.lower()
    patterns = {
        "archivo de entorno": r"(^|[/_.-])\.env($|[/?_.-])",
        "respaldo": r"(^|[/_.-])(backup|bak|dump)($|[/?_.-])",
        "credenciales o secretos": r"(^|[/_.-])(credential|credentials|secret|secrets)($|[/?_.-])",
        "volcado SQL": r"\.sql($|[?&])",
        "configuración": r"(^|[/_.-])(config|configuration)($|[/?_.-])",
        "uso interno": r"(^|[/_.-])(internal|interno|confidential|confidencial|restricted|restringido)($|[/_.-])",
        "datos laborales": r"(^|[/_.-])(payroll|nomina|employee|employees|empleado|empleados)($|[/_.-])",
        "datos financieros": r"(^|[/_.-])(financial|finance|finanzas|accounting|contabilidad)($|[/_.-])",
    }
    return [label for label, pattern in patterns.items() if re.search(pattern, value)]


def _rdap(fetch, report, registrable_domain):
    target = _dns_name(report["target"])
    try:
        target = target.encode("idna").decode("ascii")
        registrable = _dns_name(registrable_domain).encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Dominio RDAP inválido") from error
    if (not re.fullmatch(r"[a-z0-9.-]+", target) or not re.fullmatch(r"[a-z0-9.-]+", registrable)
            or target != registrable and not target.endswith("." + registrable)
            or "." not in registrable):
        raise ValueError("Dominio registrable RDAP inválido")
    report["registrable_domain"] = registrable
    report["is_subdomain"] = target != registrable
    report["limitations"] = [
        "RDAP describe el registro público del dominio registrable; no demuestra propiedad ni control por parte del cliente.",
        "Para un subdominio se consulta su dominio registrable, pero los datos del registro no se atribuyen como propiedad o riesgo del subdominio.",
        "Los registros públicos pueden omitir o redactar campos; una ausencia en la respuesta se informa como no verificable.",
        "La evidencia es informativa y no genera vulnerabilidades ni modifica el Risk Score.",
    ]
    report["field_states"] = {field: "no_verificable" for field in
                              ("registrador", "creacion", "vencimiento", "estados", "nameservers")}
    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    report["query"] = bootstrap_url
    report["queries"] = [{"kind": "bootstrap", "query": bootstrap_url, "status": "error"}]
    bootstrap_code, bootstrap = fetch(bootstrap_url, {})
    report["queries"][0]["http_status"] = bootstrap_code
    if bootstrap_code != 200 or not isinstance(bootstrap, dict):
        report["rate_limited"] = bootstrap_code == 429
        report["error"] = f"IANA RDAP bootstrap respondió HTTP {bootstrap_code} o un formato inválido"
        return
    services = bootstrap.get("services")
    if not isinstance(services, list):
        report["error"] = "IANA RDAP bootstrap no incluyó services"
        return
    report["queries"][0]["status"] = "ok"
    tld = registrable.rsplit(".", 1)[-1]
    base_url = None
    for service in services:
        if (not isinstance(service, list) or len(service) != 2
                or not isinstance(service[0], list) or not isinstance(service[1], list)):
            continue
        if tld not in {_dns_name(value) for value in service[0] if isinstance(value, str)}:
            continue
        base_url = next((value for value in service[1] if isinstance(value, str)
                         and urlsplit(value).scheme == "https" and urlsplit(value).hostname), None)
        if base_url:
            break
    if not base_url:
        report.update(status="unavailable", error=f"IANA no publicó un servicio RDAP HTTPS para .{tld}")
        return
    endpoint = base_url.rstrip("/") + "/domain/" + quote(registrable, safe="")
    report["query"] = endpoint
    domain_query = {"kind": "domain", "query": endpoint, "status": "error"}
    report["queries"].append(domain_query)
    code, data = fetch(endpoint, {})
    domain_query["http_status"] = code
    if code == 404:
        domain_query["status"] = "empty"
        report.update(status="empty", registration_state="absent",
                      results=0,
                      field_states={field: "ausente_en_respuesta" for field in report["field_states"]})
        return
    if code != 200 or not isinstance(data, dict):
        report["rate_limited"] = code == 429
        report["error"] = f"Servicio RDAP respondió HTTP {code} o un formato inválido"
        return
    domain_query["status"] = "ok"
    if data.get("objectClassName") != "domain" or _dns_name(data.get("ldhName")) != registrable:
        report["error"] = "La respuesta RDAP no corresponde al dominio registrable consultado"
        return
    registrar = _rdap_registrar(data.get("entities"))
    dates = _rdap_events(data.get("events"))
    statuses = list(dict.fromkeys(value for value in data.get("status", []) if isinstance(value, str))) if isinstance(data.get("status"), list) else []
    nameservers = list(dict.fromkeys(_dns_name(value.get("ldhName")) for value in data.get("nameservers", [])
                                     if isinstance(value, dict) and _dns_name(value.get("ldhName")))) if isinstance(data.get("nameservers"), list) else []
    references = _rdap_links(data)
    states = {
        "registrador": "conocido" if registrar else "ausente_en_respuesta",
        "creacion": "conocido" if dates.get("registration") else "ausente_en_respuesta",
        "vencimiento": "conocido" if dates.get("expiration") or dates.get("registrar expiration") else "ausente_en_respuesta",
        "estados": "conocido" if statuses else "ausente_en_respuesta",
        "nameservers": "conocido" if nameservers else "ausente_en_respuesta",
    }
    report.update(results=1, registration_state="known", field_states=states,
                  registrar=registrar, dates=dates, statuses=statuses,
                  nameservers=nameservers, references=references)
    missing = [field for field, state in states.items() if state != "conocido"]
    if missing:
        report.update(status="partial", error="Respuesta RDAP sin datos públicos verificables para: " + ", ".join(missing))
    else:
        report["status"] = "ok"
    observed_at = dates.get("last update of RDAP database") or dates.get("last changed") or report["checked_at"]
    _event(report, "RDAP_REGISTRATION", registrable, observed_at=observed_at,
           dominio_registrable=registrable, subdominio_consultado=target != registrable,
           registrador=registrar, fechas=dates, estados=statuses, nameservers=nameservers,
           referencias=references, estado_campos=states, registro="conocido",
           propiedad_atribuida=False, evaluable=False, verificado=False,
           interpretacion=("Datos del registro del dominio padre; no demuestran propiedad ni riesgo del subdominio."
                           if target != registrable else "Datos públicos del registro; no demuestran propiedad por parte del cliente."))


def _rdap_events(value):
    result = {}
    if not isinstance(value, list):
        return result
    for event in value:
        if not isinstance(event, dict) or not isinstance(event.get("eventAction"), str):
            continue
        parsed = _rdap_date(event.get("eventDate"))
        if parsed and event["eventAction"] not in result:
            result[event["eventAction"]] = parsed
    return result


def _rdap_date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _rdap_registrar(value):
    if not isinstance(value, list):
        return None
    for entity in value:
        roles = entity.get("roles") if isinstance(entity, dict) else None
        if not isinstance(entity, dict) or not isinstance(roles, list) or "registrar" not in roles:
            continue
        name = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn" and isinstance(field[3], str):
                    name = field[3].strip() or None
                    break
        public_ids = [{"type": item.get("type"), "identifier": item.get("identifier")}
                      for item in entity.get("publicIds", []) if isinstance(item, dict)
                      and isinstance(item.get("type"), str) and isinstance(item.get("identifier"), str)]
        links = _rdap_links(entity)
        result = {"name": name, "handle": entity.get("handle") if isinstance(entity.get("handle"), str) else None,
                  "public_ids": public_ids, "references": links}
        return result if any((name, result["handle"], public_ids, links)) else None
    return None


def _rdap_links(value):
    result = []
    containers = [value]
    if isinstance(value, dict) and isinstance(value.get("notices"), list):
        containers.extend(item for item in value["notices"] if isinstance(item, dict))
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get("links"), list):
            continue
        for link in container["links"]:
            href = link.get("href") if isinstance(link, dict) else None
            if not isinstance(href, str) or urlsplit(href).scheme != "https" or not urlsplit(href).hostname:
                continue
            result.append({"href": href, "rel": link.get("rel") if isinstance(link.get("rel"), str) else None,
                           "type": link.get("type") if isinstance(link.get("type"), str) else None})
    unique = {}
    for link in result:
        unique.setdefault(link["href"], link)
    return list(unique.values())[:20]
