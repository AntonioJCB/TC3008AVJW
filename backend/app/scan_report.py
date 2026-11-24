"""Cobertura verificable: consultar una fuente no certifica ausencia de riesgos."""
import ipaddress

from app.osint_normalization import normalizar_ip, parsear_servicio
from app.scan_scope import scope_allows_domain, scope_allows_ip
from app.spiderfoot_passive import reports as passive_reports


_SECURITY_PROVIDERS = {
    "google_dns_doh": "Postura DNS mediante Google Public DNS DoH",
    "internetdb": "Servicios y vulnerabilidades publicados por InternetDB",
}

_DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))


def _is_documentation_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in _DOCUMENTATION_NETWORKS)


def _security_checks(outcomes, target):
    checks = []
    is_ip = normalizar_ip(target) is not None
    spiderfoot = outcomes.get("SpiderFoot") or {}
    for report in passive_reports(spiderfoot.get("contenido")):
        provider = report.get("provider")
        if report.get("target") != target or report.get("status") not in {"ok", "empty"}:
            continue
        if provider == "google_dns_doh" and (is_ip or not report.get("checks")):
            continue
        if provider == "internetdb" and not is_ip:
            continue
        if provider not in _SECURITY_PROVIDERS:
            continue
        checks.append({
            "fuente": "SpiderFoot", "proveedor": provider,
            "descripcion": _SECURITY_PROVIDERS[provider], "estado": report["status"],
            "comprobaciones": len(report.get("checks") or []),
        })
    return checks


def inventory(client, organization_id):
    rows = []
    while True:
        page = client.table("activos").select("id,tipo,valor,visto_primera_vez").eq("organizacion_id", organization_id).order("id").range(len(rows), len(rows) + 999).execute().data or []
        rows.extend(page)
        if len(page) < 1000:
            return rows


def build_coverage(assets, outcomes, scope, initial_targets):
    result = []
    for asset in assets:
        value, kind = asset["valor"], asset["tipo"]
        target = (parsear_servicio(value) or {}).get("ip") if kind == "servicio" else value
        is_ip = bool(target and normalizar_ip(target))
        allowed = bool(target and (scope_allows_ip(scope, target) if is_ip else scope_allows_domain(scope, target)))
        compatible = kind in {"dominio", "subdominio", "ip", "servicio"}
        queries = [{**query, "fuente": name} for name, outcome in outcomes.items()
                   for query in outcome.get("consultas", []) if query["objetivo"] == target]
        complete = any(query["estado"] == "completado" for query in queries)
        security_checks = _security_checks(outcomes, target) if target else []
        pending = any(target in outcome.get("objetivos_pendientes", []) for outcome in outcomes.values())
        omitted_reason = next((
            outcome.get("objetivos_omitidos", {}).get(target)
            for outcome in outcomes.values()
            if outcome.get("objetivos_omitidos", {}).get(target)
        ), None)
        historical = bool(is_ip and _is_documentation_address(target)) or bool(
            omitted_reason and "sintético histórico" in omitted_reason
        )
        no_compatible_module = bool(
            omitted_reason and "Sin módulos OSINT pasivos" in omitted_reason
        )
        classification = (
            "historico_sintetico" if historical else
            "sin_compatibilidad" if not compatible or no_compatible_module else
            "fuera_alcance" if not allowed else
            "sin_evaluacion"
        )
        reason = ("Activo histórico/sintético basado en una dirección reservada para documentación" if is_ip and _is_documentation_address(target) else
                  "Tipo sin consulta compatible en las fuentes configuradas" if not compatible else
                  "Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor" if not allowed else
                  omitted_reason if omitted_reason else
                  "Límite de objetivos o tiempo de ejecución" if pending else
                  "Consulta con errores o incidencias" if any(q["estado"] != "completado" for q in queries) else
                  "Sin registro de consulta para este activo" if not queries else None)
        result.append({**asset, "objetivo": target, "incluido": bool(queries), "consultado": complete,
                       "motivo": reason, "consultas": queries, "previsto_al_inicio": target in initial_targets,
                       "clasificacion_exposicion": classification,
                       "evaluado_seguridad": bool(security_checks),
                       "comprobaciones_seguridad": security_checks,
                       "evaluacion_seguridad": (
                           "Comprobaciones OSINT pasivas de seguridad aplicables completadas; no equivalen a una auditoría activa."
                           if security_checks else
                           "Registro histórico o sintético no confirmado; se excluye del inventario operativo."
                           if classification == "historico_sintetico" else
                           "Activo conocido fuera del alcance autorizado; no se consultó como objetivo independiente."
                           if classification == "fuera_alcance" else
                           "Ninguna herramienta configurada admite una evaluación de seguridad para este tipo de activo."
                           if classification == "sin_compatibilidad" else
                           "Solo hubo descubrimiento o consultas informativas; no existe evaluación de seguridad suficiente."
                       )})
    pending_targets = sorted({target for outcome in outcomes.values() for target in outcome.get("objetivos_pendientes", [])})
    omitted_targets = {target: reason for outcome in outcomes.values()
                       for target, reason in outcome.get("objetivos_omitidos", {}).items()}
    actionable_pending = set(pending_targets) - set(omitted_targets)
    return {"version": 1, "activos": result, "objetivos_pendientes": pending_targets,
            "objetivos_omitidos": omitted_targets,
            "cobertura_incompleta": bool(actionable_pending or any(
                row["clasificacion_exposicion"] == "sin_evaluacion" and row["motivo"]
                for row in result
            )),
            "fuentes": {name: {"estado": outcome["estado"], "error": outcome.get("error"), "consultas": outcome.get("consultas", []), "modulos": [{key: value for key, value in report.items() if key not in {"events", "response"}} for report in passive_reports(outcome.get("contenido"))] if name == "SpiderFoot" else []} for name, outcome in outcomes.items()}}
