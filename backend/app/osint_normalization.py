from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
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
        observed_at = fecha_iso(entry.get("entry_timestamp")) or fecha_iso(entry.get("not_before"))
        for name in names:
            def certificate_facts(wildcard: bool) -> list[dict[str, Any]]:
                return [
                    {"atributo": "descubierto", "observado_en": observed_at},
                    {
                        "atributo": "certificado",
                        "observado_en": observed_at,
                        "datos": {
                            "crtsh_id": entry.get("id"),
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


def _shodan_hosts(raw: Any) -> list[Any]:
    if isinstance(raw, dict) and isinstance(raw.get("matches"), list):
        return raw["matches"]
    return raw if isinstance(raw, list) else [raw]


def _shodan_ip(host: dict[str, Any], result: dict[str, Any]) -> str | None:
    ip = normalizar_ip(str(host.get("ip_str") or ""))
    if ip is None:
        _discard(result, "valor_invalido", host.get("ip_str", host.get("ip")))
    return ip


def _shodan_in_scope(host: dict[str, Any], ip: str, domain: str, known_ips: set[str]) -> bool:
    for name in [*_list(host.get("hostnames")), *_list(host.get("domains"))]:
        normalized = normalizar_dominio(name) if isinstance(name, str) else None
        if normalized and clasificar_dominio(normalized[0], domain):
            return True
    return ip in known_ips


def _add_shodan_host_facts(host: dict[str, Any], ip: str, result: dict[str, Any]) -> str | None:
    observed_at = fecha_iso(host.get("last_update"))
    info = {
        key: value
        for key, value in (("asn", host.get("asn")), ("organizacion", host.get("org")))
        if value
    }
    facts = [{"atributo": "descubierto", "observado_en": observed_at}]
    if info:
        facts.append({"atributo": "info_host", "datos": info, "observado_en": observed_at})
    _add_ip(result, ip, facts)
    return observed_at


def _add_shodan_host_cves(host: dict[str, Any], ip: str, observed_at: str | None, result: dict[str, Any]) -> None:
    for cve in _list(host.get("vulns")):
        if isinstance(cve, str) and REGEX_CVE.search(cve):
            _add_ip(
                result,
                ip,
                [{"atributo": "cve", "datos": {"cve": cve.upper(), "verificado": None}, "observado_en": observed_at}],
            )


def _add_shodan_hostnames(
    host: dict[str, Any], ip: str, domain: str, observed_at: str | None, result: dict[str, Any]
) -> None:
    facts = [
        {"atributo": "descubierto", "observado_en": observed_at},
        {"atributo": "resuelve_a", "datos": {"ip": ip}, "observado_en": observed_at},
    ]
    for hostname in _list(host.get("hostnames")):
        _add_name(result, hostname, domain, facts)


def _add_shodan_banner(
    banner: Any, ip: str, observed_at: str | None, result: dict[str, Any]
) -> None:
    if not _object(banner):
        return
    try:
        port = int(banner.get("port"))
    except (TypeError, ValueError):
        port = 0
    protocol = banner.get("transport") if isinstance(banner.get("transport"), str) else "tcp"
    banner_time = fecha_iso(banner.get("timestamp")) or observed_at
    service = _add_service(
        result,
        ip,
        port,
        protocol,
        [
            {"atributo": "descubierto", "observado_en": banner_time},
            {
                "atributo": "servicio_expuesto",
                "observado_en": banner_time,
                "datos": {
                    "producto": banner.get("product"),
                    "version": banner.get("version"),
                    "cpe": sorted(map(str, _list(banner.get("cpe")))),
                },
            },
        ],
    )
    if service:
        _add_shodan_service_cves(banner.get("vulns"), service, banner_time, result)


def _add_shodan_service_cves(
    vulnerabilities: Any, service: str, observed_at: str | None, result: dict[str, Any]
) -> None:
    if not _object(vulnerabilities):
        return
    for cve_id, detail in vulnerabilities.items():
        if REGEX_CVE.search(cve_id):
            _observation(
                result,
                "servicio",
                service,
                "cve",
                {"cve": cve_id.upper(), "verificado": detail.get("verified") if _object(detail) else None},
                observed_at,
            )


def _adapt_shodan(raw: Any, domain: str, in_scope_ips: list[str]) -> dict[str, Any]:
    result = _new_result()
    known_ips = {address for item in in_scope_ips if (address := normalizar_ip(item))}
    for host in _shodan_hosts(raw):
        if not _object(host):
            _format_error(result, "un objeto host", host)
            continue
        ip = _shodan_ip(host, result)
        if ip is None:
            continue
        if not _shodan_in_scope(host, ip, domain, known_ips):
            _discard(result, "fuera_de_alcance", ip)
            continue
        observed_at = _add_shodan_host_facts(host, ip, result)
        _add_shodan_host_cves(host, ip, observed_at, result)
        _add_shodan_hostnames(host, ip, domain, observed_at, result)
        banners = _list(host.get("data"))
        if not banners and "port" in host:
            # /shodan/host/search devuelve un banner por entrada ("port" al nivel
            # superior y "data" como texto); /shodan/host/{ip} trae data[] de banners.
            banners = [host]
        for banner in banners:
            _add_shodan_banner(banner, ip, observed_at, result)
    return result


def _add_harvester_host(entry: Any, domain: str, result: dict[str, Any]) -> None:
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
    facts = [{"atributo": "descubierto"}]
    if address:
        facts.append({"atributo": "resuelve_a", "datos": {"ip": address}})
    hostname = _add_name(result, name, domain, facts)
    if hostname and address:
        _add_ip(result, address, [{"atributo": "descubierto"}])


def _adapt_harvester(raw: Any, domain: str) -> dict[str, Any]:
    result = _new_result()
    if not _object(raw):
        return _format_error(result, "un objeto", raw)
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
    event_type = str(event.get("type") or event.get("event_type") or "")
    data = event.get("data", "").strip() if isinstance(event.get("data"), str) else ""
    module = event.get("module") if isinstance(event.get("module"), str) else None
    origin = str(event.get("source") or event.get("source_data") or "")
    base = [{"atributo": "descubierto", "datos": {"modulo": module}}]

    if event_type in names:
        _add_name(result, data, domain, base)
    elif event_type in ips:
        _add_ip(result, data, base)
    elif event_type in emails:
        _add_email(result, data, domain, base)
    elif event_type in ports:
        _spiderfoot_port(result, event_type, data, module)
    elif cve_types.fullmatch(event_type):
        _spiderfoot_cve(result, event_type, data, origin, module, domain)
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
    cve_types = re.compile(r"^VULNERABILITY_CVE_(CRITICAL|HIGH|MEDIUM|LOW)$")
    for event in raw:
        _adapt_spiderfoot_event(event, domain, result, names, ips, emails, ports, cve_types)
    return result


ADAPTERS = {
    "crt.sh": _adapt_crtsh,
    "Shodan": _adapt_shodan,
    "theHarvester": _adapt_harvester,
    "SpiderFoot": _adapt_spiderfoot,
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
    if source == "Shodan":
        result = _adapt_shodan(raw, canonical_domain[0], in_scope_ips or [])
    else:
        result = ADAPTERS[source](raw, canonical_domain[0])
    return {
        "observaciones": deduplicar_local(result["observaciones"]),
        "descartadas": result["descartadas"],
    }