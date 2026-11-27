from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from app.spiderfoot_passive import (
    MODULES as PASSIVE_MODULES,
    PASSIVE_DNS_MODULES,
    reports as passive_reports,
)
ASSET_TYPES = {"dominio", "subdominio", "ip", "correo", "servicio"}
ATTRIBUTES = {
    "descubierto",
    "certificado",
    "servicio_expuesto",
    "resuelve_a",
    "cve",
    "info_host",
}
REGEX_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DNS_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
SERVICE = re.compile(r"^(?:\[([^\]]+)\]|([^:\s]+)):(\d{1,5})(?:/(tcp|udp))?$", re.I)


def normalizar_dominio(entrada: str) -> tuple[str, bool] | None:
    value = entrada.strip().lower()
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    value = value.rstrip(".")
    if not value:
        return None
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not ascii_domain or len(ascii_domain) > 253:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not DNS_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return ascii_domain, wildcard


def clasificar_dominio(host: str, dominio_principal: str) -> str | None:
    if host == dominio_principal:
        return "dominio"
    if host.endswith(f".{dominio_principal}"):
        return "subdominio"
    return None


def normalizar_ip(entrada: str) -> str | None:
    try:
        return ipaddress.ip_address(entrada.strip()).compressed.lower()
    except ValueError:
        return None


def valor_servicio(ip: str, puerto: int, protocolo: str) -> str | None:
    protocol = protocolo.strip().lower()
    if not isinstance(puerto, int) or not 1 <= puerto <= 65535:
        return None
    if protocol not in {"tcp", "udp"}:
        return None
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{puerto}/{protocol}"


def parsear_servicio(entrada: str) -> dict[str, Any] | None:
    match = SERVICE.fullmatch(entrada.strip())
    if not match:
        return None
    ip = normalizar_ip(match.group(1) or match.group(2) or "")
    port = int(match.group(3))
    if ip is None or not 1 <= port <= 65535:
        return None
    return {"ip": ip, "puerto": port, "protocolo": (match.group(4) or "tcp").lower()}


def normalizar_correo(entrada: str) -> str | None:
    value = entrada.strip().lower()
    if value.startswith("mailto:"):
        value = value[len("mailto:"):]
    parts = value.split("@")
    if len(parts) != 2 or not re.fullmatch(r"[a-z0-9._%+-]{1,64}", parts[0]):
        return None
    domain = normalizar_dominio(parts[1])
    if domain is None or domain[1]:
        return None
    return f"{parts[0]}@{domain[0]}"


def fecha_iso(value: Any) -> str | None:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            timestamp = value / 1000 if value >= 1e11 else value
            date = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif isinstance(value, str) and value.strip():
            text = value.strip()
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?", text):
                text = text.replace(" ", "T", 1) + "Z"
            date = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            date = date.astimezone(timezone.utc)
        else:
            return None
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return date.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_canonico(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_contenido(value: Any) -> str:
    return hashlib.sha256(json_canonico(value).encode("utf-8")).hexdigest()


def deduplicar_local(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for observation in observations:
        key = "|".join(
            (
                observation["tipo"],
                observation["valor"],
                observation["atributo"],
                json_canonico(observation.get("datos", {})),
            )
        )
        previous = unique.get(key)
        if previous is None:
            unique[key] = observation
            continue
        current_date = observation.get("observado_en")
        previous_date = previous.get("observado_en")
        if current_date and (not previous_date or current_date < previous_date):
            previous["observado_en"] = current_date
    return list(unique.values())


def _object(value: Any) -> bool:
    return isinstance(value, dict)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _new_result() -> dict[str, list[dict[str, Any]]]:
    return {"observaciones": [], "descartadas": []}


def _discard(result: dict[str, Any], reason: str, value: Any) -> None:
    result["descartadas"].append({"motivo": reason, "entrada": value})


def _observation(
    result: dict[str, Any],
    asset_type: str,
    value: str,
    attribute: str,
    details: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> None:
    item = {
        "tipo": asset_type,
        "valor": value,
        "atributo": attribute,
        "datos": details or {},
    }
    if observed_at:
        item["observado_en"] = observed_at
    result["observaciones"].append(item)


def _add_name(
    result: dict[str, Any],
    value: Any,
    domain: str,
    facts: list[dict[str, Any]] | Any,
) -> str | None:
    normalized = normalizar_dominio(value) if isinstance(value, str) else None
    if normalized is None:
        _discard(result, "valor_invalido", value)
        return None
    canonical, wildcard = normalized
    asset_type = clasificar_dominio(canonical, domain)
    if asset_type is None:
        _discard(result, "fuera_de_alcance", canonical)
        return None
    selected_facts = facts(wildcard) if callable(facts) else facts
    for fact in selected_facts:
        _observation(
            result,
            asset_type,
            canonical,
            fact["atributo"],
            fact.get("datos"),
            fact.get("observado_en"),
        )
    return canonical


def _add_ip(result: dict[str, Any], value: Any, facts: list[dict[str, Any]]) -> str | None:
    address = normalizar_ip(value) if isinstance(value, str) else None
    if address is None:
        _discard(result, "valor_invalido", value)
        return None
    for fact in facts:
        _observation(
            result, "ip", address, fact["atributo"], fact.get("datos"), fact.get("observado_en")
        )
    return address


def _add_email(
    result: dict[str, Any], value: Any, domain: str, facts: list[dict[str, Any]]
) -> None:
    email = normalizar_correo(value) if isinstance(value, str) else None
    if email is None:
        _discard(result, "valor_invalido", value)
        return
    if clasificar_dominio(email.rsplit("@", 1)[1], domain) is None:
        _discard(result, "fuera_de_alcance", email)
        return
    for fact in facts:
        _observation(
            result, "correo", email, fact["atributo"], fact.get("datos"), fact.get("observado_en")
        )


def _add_service(
    result: dict[str, Any], ip: str, port: int, protocol: str, facts: list[dict[str, Any]]
) -> str | None:
    service = valor_servicio(ip, port, protocol)
    if service is None:
        _discard(result, "valor_invalido", f"{ip}:{port}/{protocol}")
        return None
    for fact in facts:
        _observation(
            result, "servicio", service, fact["atributo"], fact.get("datos"), fact.get("observado_en")
        )
    return service


def _format_error(result: dict[str, Any], expected: str, received: Any) -> dict[str, Any]:
    value_type = "arreglo" if isinstance(received, list) else type(received).__name__
    _discard(result, "valor_invalido", f"Se esperaba {expected}; se recibió {value_type}")
    return result


def _adapt_crtsh(raw: Any, domain: str) -> dict[str, Any]:
    result = _new_result()
    if isinstance(raw, dict) and raw.get("version") == 1:
        raw = raw.get("entries")
    if not isinstance(raw, list):
        return _format_error(result, "un arreglo", raw)
    for entry in raw:
        if not _object(entry):
            _discard(result, "valor_invalido", entry)
            continue
        names: set[str] = set()
        for field in (entry.get("name_value"), entry.get("common_name")):
            if isinstance(field, str):
                names.update(line.strip() for line in re.split(r"\r?\n", field) if line.strip())
        observed_at = (fecha_iso(entry.get("entry_timestamp"))
                       or fecha_iso(entry.get("min_entry_timestamp"))
                       or fecha_iso(entry.get("not_before")))
        for name in names:
            def certificate_facts(wildcard: bool) -> list[dict[str, Any]]:
                return [
                    {"atributo": "descubierto", "observado_en": observed_at},
                    {
                        "atributo": "certificado",
                        "observado_en": observed_at,
                        "datos": {
                            "crtsh_id": entry.get("id") or entry.get("min_cert_id"),
                            "serie": entry.get("serial_number"),
                            "emisor": entry.get("issuer_name"),
                            "valido_desde": fecha_iso(entry.get("not_before")),
                            "valido_hasta": fecha_iso(entry.get("not_after")),
                            "comodin": wildcard,
                        },
                    },
                ]

            _add_name(result, name, domain, certificate_facts)
    return result


def _add_harvester_host(entry: Any, domain: str, result: dict[str, Any], sources: list[str] | None = None) -> None:
    if not isinstance(entry, str):
        _discard(result, "valor_invalido", entry)
        return
    if normalizar_ip(entry):
        _add_ip(result, entry, [{"atributo": "descubierto"}])
        return
    delimiter = entry.find(":")
    name = entry if delimiter == -1 else entry[:delimiter]
    address_text = "" if delimiter == -1 else entry[delimiter + 1:]
    address = normalizar_ip(address_text) if address_text else None
    facts = [{"atributo": "descubierto", "datos": {"proveedores": sources}}] if sources else [{"atributo": "descubierto"}]
    if address:
        facts.append({"atributo": "resuelve_a", "datos": {"ip": address}})
    hostname = _add_name(result, name, domain, facts)
    if hostname and address:
        _add_ip(result, address, [{"atributo": "descubierto"}])


def _adapt_harvester(raw: Any, domain: str) -> dict[str, Any]:
    result = _new_result()
    if not _object(raw):
        return _format_error(result, "un objeto", raw)
    if raw.get("items"):
        for item in raw["items"]:
            if not isinstance(item, dict):
                _discard(result, "valor_invalido", item)
                continue
            kind = str(item.get("type", "")).lower()
            value = item.get("value")
            providers = [source for source in item.get("sources", []) if isinstance(source, str)]
            facts = [{"atributo": "descubierto", "datos": {"proveedores": providers}}] if providers else [{"atributo": "descubierto"}]
            if kind in {"hostname", "host"}:
                _add_harvester_host(value, domain, result, providers)
            elif kind == "ip":
                _add_ip(result, value, facts)
            elif kind == "email":
                _add_email(result, value, domain, facts)
            elif kind == "url" and isinstance(value, str):
                try:
                    hostname = urlsplit(value).hostname
                except ValueError:
                    hostname = None
                _add_harvester_host(hostname, domain, result, providers)
            else:
                _discard(result, "tipo_no_soportado", item)
        return result
    for entry in [*_list(raw.get("hosts")), *_list(raw.get("vhosts"))]:
        _add_harvester_host(entry, domain, result)
    for address in _list(raw.get("ips")):
        _add_ip(result, address, [{"atributo": "descubierto"}])
    for email in _list(raw.get("emails")):
        _add_email(result, email, domain, [{"atributo": "descubierto"}])
    for asn in _list(raw.get("asns")):
        _discard(result, "tipo_no_soportado", asn)
    return result


def _spiderfoot_cve(
    result: dict[str, Any], event_type: str, data: str, origin: str, module: str | None, domain: str
) -> None:
    cve_match = REGEX_CVE.search(data)
    if not cve_match:
        _discard(result, "valor_invalido", data)
        return
    fact = {
        "atributo": "cve",
        "datos": {
            "cve": cve_match.group(0).upper(),
            "severidad_fuente": event_type.removeprefix("VULNERABILITY_CVE_").lower(),
            "modulo": module,
        },
    }
    service_details = parsear_servicio(origin)
    if service_details:
        _add_service(
            result,
            service_details["ip"],
            service_details["puerto"],
            service_details["protocolo"],
            [fact],
        )
    elif normalizar_ip(origin):
        _add_ip(result, origin, [fact])
    elif normalizar_dominio(origin):
        _add_name(result, origin, domain, [fact])
    else:
        _discard(result, "sin_activo_asociado", origin)


def _adapt_spiderfoot_event(
    event: Any,
    domain: str,
    result: dict[str, Any],
    names: set[str],
    ips: set[str],
    emails: set[str],
    ports: set[str],
    cve_types: re.Pattern[str],
) -> None:
    if not _object(event):
        _discard(result, "valor_invalido", event)
        return
    # SpiderFoot exporta la decisión del analista junto al evento.
    if str(event.get("false_positive", "")).strip().lower() in {"1", "true"}:
        _discard(result, "falso_positivo_fuente", event.get("data"))
        return
    event_type = str(event.get("type") or event.get("event_type") or "")
    data = event.get("data", "").strip() if isinstance(event.get("data"), str) else ""
    module = event.get("module") if isinstance(event.get("module"), str) else None
    if module == "SpiderFoot UI":
        _discard(result, "evento_interno_spiderfoot", event_type)
        return
    origin = str(event.get("source") or event.get("source_data") or "")
    base = [{"atributo": "descubierto", "datos": {"modulo": module}}]

    if event_type in names:
        _add_name(result, data, domain, base)
    elif event_type in ips:
        _add_ip(result, data, base)
        address = normalizar_ip(data)
        origin_name = normalizar_dominio(origin)
        if address and origin_name and clasificar_dominio(origin_name[0], domain):
            _add_name(result, origin_name[0], domain, [{"atributo": "resuelve_a", "datos": {"ip": address, "modulo": module}}])
    elif event_type in emails:
        _add_email(result, data, domain, base)
    elif event_type in ports:
        _spiderfoot_port(result, event_type, data, module)
    elif cve_types.fullmatch(event_type):
        _spiderfoot_cve(result, event_type, data, origin, module, domain)
    elif event_type in {"DNS_POSTURE", "COMMONCRAWL_URL", "RDAP_REGISTRATION", "URLSCAN_HISTORY", "URLSCAN_HTTP_STATUS", "URLSCAN_REDIRECT", "URLSCAN_HTTP_REDIRECT", "URLSCAN_TLS_CERTIFICATE", "URLSCAN_PAGE_METADATA", "URLSCAN_SECURITY_HEADERS", "URLSCAN_VERDICT", "WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY", "SOFTWARE_USED", "OPERATING_SYSTEM", "TCP_PORT_OPEN_BANNER", "UDP_PORT_OPEN_INFO", "PROVIDER_PORT", "VULNERABILITY_GENERAL", "VULNERABILITY_DISCLOSURE"}:
        fact = {"atributo": "info_host", "datos": {"modulo": module, "tipo_evento": event_type, "valor": data}}
        service = parsear_servicio(origin)
        if service:
            _add_service(result, service["ip"], service["puerto"], service["protocolo"], [fact])
        elif normalizar_ip(origin):
            _add_ip(result, origin, [fact])
        else:
            if origin.startswith(("https://", "http://")):
                try:
                    origin = urlsplit(origin).hostname or ""
                except ValueError:
                    origin = ""
            if normalizar_dominio(origin):
                _add_name(result, origin, domain, [fact])
            else:
                _discard(result, "sin_activo_asociado", origin)
    else:
        _discard(result, "tipo_no_soportado", event_type)


def _spiderfoot_port(result: dict[str, Any], event_type: str, data: str, module: str | None) -> None:
    service_details = parsear_servicio(data)
    if service_details is None:
        _discard(result, "valor_invalido", data)
        return
    protocol = "udp" if event_type.startswith("UDP") else "tcp"
    _add_service(
        result,
        service_details["ip"],
        service_details["puerto"],
        protocol,
        [
            {"atributo": "descubierto", "datos": {"modulo": module}},
            {"atributo": "servicio_expuesto", "datos": {"modulo": module}},
        ],
    )


def _adapt_spiderfoot(raw: Any, domain: str) -> dict[str, Any]:
    result = _new_result()
    if not isinstance(raw, list):
        return _format_error(result, "un arreglo de eventos", raw)
    names = {"INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME"}
    ips = {"IP_ADDRESS", "IPV6_ADDRESS"}
    emails = {"EMAILADDR", "EMAILADDR_GENERIC", "EMAIL_ADDRESS"}
    ports = {"TCP_PORT_OPEN", "UDP_PORT_OPEN"}
    cve_types = re.compile(r"^VULNERABILITY_CVE_(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)$")
    passive_events = [event for event in raw
                      if isinstance(event, dict) and event.get("module") in PASSIVE_MODULES]
    summaries = passive_reports(passive_events)
    if passive_events and not summaries:
        for event in passive_events:
            _discard(result, "reporte_pasivo_invalido_o_descartado", event.get("module"))
    for summary in summaries:
        if summary["status"] not in {"ok", "partial"}:
            continue
        if summary.get("provider") == "google_dns_doh":
            target = summary.get("target")
            for check in summary.get("checks") or []:
                if not isinstance(check, dict) or check.get("check") not in {"a", "aaaa"} or check.get("state") != "present":
                    continue
                for record in check.get("records") or []:
                    if not isinstance(record, dict) or not isinstance(target, str):
                        continue
                    if str(record.get("name", "")).rstrip(".").lower() != target.rstrip(".").lower():
                        continue
                    address = normalizar_ip(record.get("data")) if isinstance(record.get("data"), str) else None
                    if not address or not ipaddress.ip_address(address).is_global:
                        continue
                    fact = {"atributo": "resuelve_a", "datos": {"ip": address, "modulo": summary["module"],
                            "tipo_registro": check["check"].upper()}, "observado_en": check.get("checked_at")}
                    if _add_name(result, target, domain, [fact]):
                        _add_ip(result, address, [{"atributo": "descubierto", "datos": {"modulo": summary["module"]},
                                                  "observado_en": check.get("checked_at")}])
        for fact in summary["events"]:
            if not isinstance(fact, dict):
                continue
            # Events must refer to the exact queried host, or a service on that IP.
            origin = fact.get("source_data", "")
            service = parsear_servicio(origin) if isinstance(origin, str) else None
            if origin != summary["target"] and (service or {}).get("ip") != summary["target"]:
                _discard(result, "fuera_de_alcance", origin)
                continue
            before = len(result["observaciones"])
            _adapt_spiderfoot_event({**fact, "module": summary["module"]}, domain, result, names, ips, emails, ports, cve_types)
            for observation in result["observaciones"][before:]:
                observation["datos"].update(fact.get("metadata") or {})
                observation["datos"]["modulo"] = summary["module"]
                observed = fecha_iso(fact.get("observed_at"))
                if observed:
                    observation["observado_en"] = observed
    for event in raw:
        if not (isinstance(event, dict) and event.get("module") in PASSIVE_MODULES):
            origin = event.get("source_data", "") if isinstance(event, dict) else ""
            if (isinstance(event, dict) and event.get("module") in PASSIVE_DNS_MODULES
                    and isinstance(origin, str)
                    and re.search(r'"profile"\s*:\s*"baxter-passive-v1"', origin)):
                _discard(result, "evento_derivado_reporte_pasivo", event.get("event_type", event.get("type")))
                continue
            _adapt_spiderfoot_event(event, domain, result, names, ips, emails, ports, cve_types)
    return result


def _adapt_web(raw: Any, domain: str) -> dict[str, Any]:
    result = _new_result()
    if not isinstance(raw, list):
        return _format_error(result, "un arreglo de comprobaciones", raw)
    checks = {"tls_verificado", "tls_por_expirar", "tls_invalido", "http_sin_redireccion"}
    for event in raw:
        if not isinstance(event, dict) or event.get("check") not in checks or event.get("validation_mode") != "active-authorized-v1":
            _discard(result, "valor_invalido", event)
            continue
        host = event.get("host")
        if not isinstance(host, str):
            _discard(result, "valor_invalido", event)
            continue
        data = {key: value for key, value in event.items() if key != "host"}
        data["comprobacion_activa"] = True
        _add_name(result, host, domain, [{"atributo": "info_host", "datos": data}])
    return result


def _adapt_censys(raw: Any, domain: str, in_scope_ips: list[str]) -> dict[str, Any]:
    """Platform v3: hosts[].result.resource. Nunca atribuye servicios solo por DNS."""
    result = _new_result()
    if not isinstance(raw, dict) or not isinstance(raw.get("hosts"), list):
        return _format_error(result, "un objeto Censys con hosts[]", raw)
    allowed = {ip for value in in_scope_ips if (ip := normalizar_ip(value))}
    dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    resolved = {ip for value in _list(dns.get("ips")) if isinstance(value, str) and (ip := normalizar_ip(value))}
    if dns.get("dominio") == domain:
        for ip in sorted(resolved):
            _add_name(result, domain, domain, [{"atributo": "resuelve_a", "datos": {"ip": ip, "metodo": "dns_local"}}])
            _add_ip(result, ip, [{"atributo": "descubierto", "datos": {"metodo": "dns_local"}}])
    for payload in raw["hosts"]:
        resource = payload.get("result", {}).get("resource") if isinstance(payload, dict) and isinstance(payload.get("result"), dict) else None
        if not isinstance(resource, dict):
            _format_error(result, "result.resource de Censys", payload)
            continue
        ip = normalizar_ip(str(resource.get("ip", "")))
        # La correlación de DNS permite inventario, no autoriza la infraestructura.
        if not ip or ip not in resolved:
            _discard(result, "fuera_de_alcance", resource.get("ip"))
            continue
        if ip not in allowed:
            if resource.get("services"):
                _discard(result, "servicios_sin_ip_autorizada", ip)
            continue
        for service in _list(resource.get("services")):
            if not isinstance(service, dict):
                _format_error(result, "un servicio Censys", service)
                continue
            protocol = str(service.get("transport_protocol", "")).lower()
            if protocol not in {"tcp", "udp"}:
                _discard(result, "protocolo_no_soportado", protocol)
                continue
            port = service.get("port")
            if not isinstance(port, int) or isinstance(port, bool):
                _discard(result, "valor_invalido", port)
                continue
            observed_at = fecha_iso(service.get("scan_time"))
            value = _add_service(result, ip, port, protocol, [{
                "atributo": "servicio_expuesto", "observado_en": observed_at,
                "datos": {"protocolo_aplicacion": service.get("protocol"),
                          "software": _list(service.get("software")), "atribucion": "ip_autorizada_en_servidor"},
            }])
            if not value:
                continue
            for vuln in _list(service.get("vulns")):
                cve = vuln.get("id") if isinstance(vuln, dict) else None
                if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, flags=re.I):
                    _observation(result, "servicio", value, "cve", {
                        "cve": cve.upper(), "verificado": None,
                        "severidad_fuente": vuln.get("severity"),
                        "confianza_fuente": vuln.get("confidence"),
                    }, observed_at)
    return result


ADAPTERS = {
    "crt.sh": _adapt_crtsh,
    "Censys": _adapt_censys,
    "theHarvester": _adapt_harvester,
    "SpiderFoot": _adapt_spiderfoot,
    "Web": _adapt_web,
}


def adaptar(
    source: str,
    raw: Any,
    domain: str,
    in_scope_ips: list[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    if source not in ADAPTERS:
        raise ValueError(f"Fuente OSINT no soportada: {source}")
    canonical_domain = normalizar_dominio(domain)
    if canonical_domain is None:
        raise ValueError("Dominio principal inválido")
    if source in {"Censys"}:
        result = ADAPTERS[source](raw, canonical_domain[0], in_scope_ips or [])
    else:
        result = ADAPTERS[source](raw, canonical_domain[0])
    return {
        "observaciones": deduplicar_local(result["observaciones"]),
        "descartadas": result["descartadas"],
    }
