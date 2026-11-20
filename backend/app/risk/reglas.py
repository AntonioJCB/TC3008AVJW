"""Evaluadores de reglas de riesgo.

Cada regla de `reglas_riesgo` (identificada por `codigo`) tiene aquí una
función que decide, a partir de las observaciones, qué activos la cumplen.
La base de datos define el CATÁLOGO (nombre, severidad, peso); este archivo
define la LÓGICA. Una regla del catálogo sin evaluador aquí se reporta como
"sin_evaluador" en la cobertura, nunca se da por cumplida ni por descartada.

La disponibilidad de un evaluador no implica que los módulos configurados
produzcan su evidencia. La activación depende del catálogo y de source_policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Callable, Iterable, Sequence

from app.osint_normalization import parsear_servicio
from app.risk.modelos import Candidato, Obs

# crt.sh lista certificados históricos: estos hallazgos requieren confirmar el
# certificado servido actualmente antes de aportar puntos al Risk Score.
VENTANA_EXPIRADO_DIAS = 90
DIAS_POR_EXPIRAR = 30
PATRON_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

PUERTOS_ADMIN_REMOTA = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
PUERTOS_BASE_DE_DATOS = {
    1433: "SQL Server", 1521: "Oracle", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


def _agrupar(observaciones: Iterable[Obs]) -> dict[str, list[Obs]]:
    grupos: dict[str, list[Obs]] = {}
    for o in observaciones:
        grupos.setdefault(o.activo_id, []).append(o)
    return grupos


def _fecha(valor: object) -> datetime | None:
    if not isinstance(valor, str):
        return None
    try:
        d = datetime.fromisoformat(valor.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------
# INFRA-001 / INFRA-002: puertos peligrosos expuestos
# ---------------------------------------------------------------------


def _evaluador_puertos(puertos: dict[int, str]) -> Callable[[Sequence[Obs], datetime], list[Candidato]]:
    def evaluar(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
        candidatos: list[Candidato] = []
        servicios = (o for o in observaciones if o.tipo == "servicio" and o.atributo == "servicio_expuesto")
        for activo_id, grupo in _agrupar(servicios).items():
            s = parsear_servicio(grupo[0].valor)
            if s is None or s["protocolo"] != "tcp" or s["puerto"] not in puertos:
                continue
            producto = next((o.datos["producto"] for o in grupo if o.datos.get("producto")), None)
            candidatos.append(
                Candidato(
                    activo_id,
                    grupo,
                    {
                        "servicio": grupo[0].valor,
                        "ip": s["ip"],
                        "puerto": s["puerto"],
                        "tipo_servicio": puertos[s["puerto"]],
                        "producto": producto,
                    },
                )
            )
        return candidatos

    return evaluar


# ---------------------------------------------------------------------
# INFRA-003: vulnerabilidades conocidas (CVE) asociadas a un activo
# ---------------------------------------------------------------------


def _evaluar_cve(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    candidatos: list[Candidato] = []
    validas = [
        o for o in observaciones
        if o.tipo in {"servicio", "ip", "dominio", "subdominio"} and o.atributo == "cve"
        and isinstance(o.datos.get("cve"), str)
        and PATRON_CVE.fullmatch(o.datos["cve"])
        and o.datos.get("verificado") is True
    ]
    cves_de_servicio = {
        (service["ip"], o.datos["cve"].upper())
        for o in validas if o.tipo == "servicio"
        if (service := parsear_servicio(o.valor)) is not None
    }
    sin_duplicados = [
        o for o in validas
        if o.tipo != "ip" or (o.valor, o.datos["cve"].upper()) not in cves_de_servicio
    ]
    for activo_id, grupo in _agrupar(sin_duplicados).items():
        cves = sorted({o.datos["cve"].upper() for o in grupo})
        severidades = sorted({str(o.datos["severidad_fuente"]) for o in grupo if o.datos.get("severidad_fuente")})
        candidatos.append(
            Candidato(activo_id, grupo, {
                "activo": grupo[0].valor, "cves": cves,
                "severidades_fuente": severidades,
                "verificado_por_fuente": any(o.datos.get("verificado") is True for o in grupo),
            })
        )
    return candidatos


# ---------------------------------------------------------------------
# CONF-001 / CONF-002: certificados TLS de CT corroborados por la fuente Web.
#
# Se mira el certificado que vence más tarde para cada nombre: si incluso ese
# ya venció, no consta uno vigente en esa consulta CT. Eso no prueba el estado
# servido por el sitio. Estos evaluadores históricos dependen de Web retirada.
# ---------------------------------------------------------------------


def _vigencia_maxima(grupo: Sequence[Obs]) -> tuple[datetime, Obs] | None:
    con_fecha = [(f, o) for o in grupo if (f := _fecha(o.datos.get("valido_hasta"))) is not None]
    return max(con_fecha, key=lambda t: t[0]) if con_fecha else None


def _evaluar_cert_expirado(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    candidatos: list[Candidato] = []
    web = _agrupar(o for o in observaciones if o.fuente == "Web" and o.atributo == "info_host"
                  and o.datos.get("check") == "tls_invalido" and o.datos.get("verify_code") == 10)
    for activo_id, grupo in _agrupar(o for o in observaciones if o.atributo == "certificado").items():
        if activo_id not in web:
            continue
        vigencia = _vigencia_maxima(grupo)
        if vigencia is None:
            continue
        hasta, obs = vigencia
        dias = (ahora - hasta).days
        if hasta < ahora and dias <= VENTANA_EXPIRADO_DIAS:
            candidatos.append(
                Candidato(
                    activo_id,
                    [obs, *web[activo_id]],
                    {
                        "activo": obs.valor, "vencio_el": hasta.isoformat(), "dias_vencido": dias,
                        "serie": obs.datos.get("serie"), "emisor": obs.datos.get("emisor"),
                    },
                )
            )
    return candidatos


def _evaluar_cert_por_expirar(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    candidatos: list[Candidato] = []
    web = _agrupar(o for o in observaciones if o.fuente == "Web" and o.atributo == "info_host"
                  and o.datos.get("check") == "tls_verificado")
    for activo_id, grupo in _agrupar(o for o in observaciones if o.atributo == "certificado").items():
        current = [o for o in web.get(activo_id, [])
                   if (expiry := _fecha(o.datos.get("valid_until"))) is not None
                   and ahora <= expiry <= ahora + timedelta(days=DIAS_POR_EXPIRAR)]
        if not current:
            continue
        vigencia = _vigencia_maxima(grupo)
        if vigencia is None:
            continue
        hasta, obs = vigencia
        if ahora <= hasta <= ahora + timedelta(days=DIAS_POR_EXPIRAR):
            candidatos.append(
                Candidato(
                    activo_id,
                    [obs, *current],
                    {
                        "activo": obs.valor, "vence_el": hasta.isoformat(), "dias_restantes": (hasta - ahora).days,
                        "serie": obs.datos.get("serie"), "emisor": obs.datos.get("emisor"),
                    },
                )
            )
    return candidatos


# ---------------------------------------------------------------------
# IDEN-003: correos corporativos expuestos públicamente
# ---------------------------------------------------------------------


def _evaluar_correos(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    correos = (o for o in observaciones if o.tipo == "correo" and o.atributo == "descubierto")
    return [Candidato(a, g, {"correo": g[0].valor}) for a, g in _agrupar(correos).items()]


def _evaluar_postura_web(check: str) -> Callable[[Sequence[Obs], datetime], list[Candidato]]:
    def evaluar(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
        groups = _agrupar(
            o for o in observaciones
            if o.fuente == "Web" and o.tipo in {"dominio", "subdominio"}
            and o.atributo == "info_host" and o.datos.get("check") == check
        )
        return [Candidato(asset_id, group, {"activo": group[0].valor, **group[0].datos})
                for asset_id, group in groups.items()]
    return evaluar


def _evaluar_postura_dns(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    """Consume únicamente problemas DNS explícitos y marcados como evaluables.

    El catálogo de Supabase conserva el control de activación y del peso. Estados
    ausentes, errores y verificaciones inconclusas no se convierten por sí solos
    en hallazgos.
    """
    def inherited_issue(code: str, message: str, severity: str) -> dict:
        return {"code": code, "message": message, "severity": severity,
                "evaluable": True, "rule": "CONF-003"}

    groups = _agrupar(
        o for o in observaciones
        if o.fuente == "SpiderFoot" and o.tipo in {"dominio", "subdominio"}
        and o.atributo == "info_host" and o.datos.get("tipo_evento") == "DNS_POSTURE"
    )
    selected_by_asset: dict[str, list[Obs]] = {}
    evidence_by_asset: dict[str, list[dict]] = {}
    inherited_from: dict[str, str] = {}
    for asset_id, group in groups.items():
        for observation in group:
            issues = observation.datos.get("issues")
            if not isinstance(issues, list):
                continue
            valid = [issue for issue in issues if isinstance(issue, dict)
                     and issue.get("rule") == "CONF-003" and issue.get("evaluable") is True
                     and isinstance(issue.get("code"), str)]
            if valid:
                selected_by_asset.setdefault(asset_id, []).append(observation)
                evidence_by_asset.setdefault(asset_id, []).extend(valid)

    domain_policies = []
    for root_id, root_group in groups.items():
        for observation in root_group:
            policies = observation.datos.get("politicas_dmarc")
            if (observation.tipo == "dominio" and observation.datos.get("check") == "dmarc"
                    and observation.datos.get("estado") == "present"
                    and isinstance(policies, list) and len(policies) == 1
                    and isinstance(policies[0], dict)):
                domain_policies.append((root_id, observation, policies[0]))

    for asset_id, group in groups.items():
        if not group or group[0].tipo != "subdominio":
            continue
        exact = next((o for o in group if o.datos.get("check") == "dmarc"), None)
        if (exact is None or exact.datos.get("politicas_dmarc")
                or exact.datos.get("registros")):
            continue
        roots = [(root_id, root, policy) for root_id, root, policy in domain_policies
                 if group[0].valor.endswith("." + root.valor)]
        if not roots:
            continue
        _root_id, root, policy = max(roots, key=lambda item: len(item[1].valor))
        effective = policy.get("sp") or policy.get("p")
        inherited = []
        if effective == "none":
            inherited.append(inherited_issue(
                "DMARC_INHERITED_MONITOR_ONLY",
                f"La política DMARC heredada desde {root.valor} solo monitoriza suplantación.",
                "media",
            ))
        try:
            percentage = int(policy.get("pct", "100"))
            if 0 <= percentage < 100:
                inherited.append(inherited_issue(
                    "DMARC_INHERITED_PARTIAL_PERCENTAGE",
                    f"La política DMARC heredada desde {root.valor} se aplica a menos del 100 % de los mensajes.",
                    "baja",
                ))
        except (TypeError, ValueError):
            pass
        if inherited:
            selected_by_asset.setdefault(asset_id, []).extend((exact, root))
            evidence_by_asset.setdefault(asset_id, []).extend(inherited)
            inherited_from[asset_id] = root.valor

    candidates = []
    for asset_id, selected in selected_by_asset.items():
        unique_observations = list({observation.id: observation for observation in selected}.values())
        unique_issues = {str(issue["code"]): issue for issue in evidence_by_asset[asset_id]}
        detail = {
            "activo": groups[asset_id][0].valor,
            "problemas_dns": [unique_issues[code] for code in sorted(unique_issues)],
            "comprobaciones": sorted({str(o.datos.get("check")) for o in unique_observations}),
        }
        if asset_id in inherited_from:
            detail["dmarc_heredada_desde"] = inherited_from[asset_id]
        candidates.append(Candidato(asset_id, unique_observations, detail))
    return candidates


def _evaluar_cabeceras_urlscan(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    """Use only complete, recent, exact-host historical HTTP responses."""
    groups = _agrupar(
        o for o in observaciones
        if o.fuente == "SpiderFoot" and o.tipo in {"dominio", "subdominio"}
        and o.atributo == "info_host" and o.datos.get("tipo_evento") == "URLSCAN_SECURITY_HEADERS"
        and o.datos.get("evaluable") is True and o.datos.get("cabeceras_completas") is True
        and o.datos.get("historico") is True and o.datos.get("verificado_actual") is False
    )
    candidates = []
    for asset_id, group in groups.items():
        dated = [(date, observation) for observation in group
                 if (date := _fecha(observation.observado_en)) is not None]
        if not dated:
            continue
        latest_date = max(date for date, _observation in dated)
        latest = [observation for date, observation in dated if date == latest_date]
        issues = [issue for observation in latest for issue in observation.datos.get("issues", [])
                  if isinstance(issue, dict) and issue.get("rule") == "CONF-004"
                  and issue.get("evaluable") is True and isinstance(issue.get("code"), str)]
        if not issues:
            continue
        unique = {issue["code"]: issue for issue in issues}
        age = min((value for observation in latest
                   if isinstance((value := observation.datos.get("antiguedad_dias")), int)), default=None)
        candidates.append(Candidato(asset_id, latest, {
            "activo": latest[0].valor,
            "respuesta_observada_en": latest_date.isoformat(),
            "cabeceras_ausentes": [unique[code] for code in sorted(unique)],
            "referencias": sorted({reference for observation in latest
                                   for reference in observation.datos.get("referencias", [])
                                   if isinstance(reference, str)}),
            "historico": True, "potencial": True, "verificado_actual": False,
        }, nivel_evidencia="potencial", antiguedad_dias=age,
            motivo_no_confirmado="Evidencia histórica de urlscan; la configuración HTTP actual no fue verificada."))
    return candidates


def _evaluar_cert_proximo_urlscan(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    groups = _agrupar(
        o for o in observaciones
        if o.fuente == "SpiderFoot" and o.tipo in {"dominio", "subdominio"}
        and o.atributo == "info_host" and o.datos.get("tipo_evento") == "URLSCAN_TLS_CERTIFICATE"
        and o.datos.get("evidencia_completa") is True
        and o.datos.get("historico") is True and o.datos.get("verificado_actual") is False
    )
    candidates = []
    for asset_id, group in groups.items():
        dated = [(date, observation) for observation in group
                 if (date := _fecha(observation.observado_en)) is not None]
        if not dated:
            continue
        latest_date = max(date for date, _observation in dated)
        latest = [observation for date, observation in dated if date == latest_date]
        risky = [observation for observation in latest if observation.datos.get("evaluable") is True]
        issues = [issue for observation in risky
                  for issue in (observation.datos.get("issues")
                                if isinstance(observation.datos.get("issues"), list) else [])
                  if isinstance(issue, dict) and issue.get("rule") == "CONF-007"
                  and issue.get("evaluable") is True]
        if not risky or not issues:
            continue
        candidates.append(Candidato(asset_id, risky, {
            "activo": risky[0].valor,
            "vence_el": risky[0].datos.get("valido_hasta"),
            "dias_restantes": risky[0].datos.get("dias_restantes"),
            "emisor": risky[0].datos.get("emisor"),
            "respuesta_observada_en": latest_date.isoformat(),
            "referencias": sorted({reference for observation in risky
                                   for reference in observation.datos.get("referencias", [])
                                   if isinstance(reference, str)}),
            "historico": True, "potencial": True, "verificado_actual": False,
        }))
    return candidates


def _evaluar_http_sin_https_urlscan(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    groups = _agrupar(
        o for o in observaciones
        if o.fuente == "SpiderFoot" and o.tipo in {"dominio", "subdominio"}
        and o.atributo == "info_host" and o.datos.get("tipo_evento") == "URLSCAN_HTTP_REDIRECT"
        and o.datos.get("cadena_completa") is True and o.datos.get("evidencia_explicita") is True
        and o.datos.get("historico") is True and o.datos.get("verificado_actual") is False
    )
    candidates = []
    for asset_id, group in groups.items():
        dated = [(date, observation) for observation in group
                 if (date := _fecha(observation.observado_en)) is not None]
        if not dated:
            continue
        latest_date = max(date for date, _observation in dated)
        latest = [observation for date, observation in dated if date == latest_date]
        risky = [observation for observation in latest
                 if observation.datos.get("estado") == "http_sin_redireccion_https"
                 and observation.datos.get("evaluable") is True]
        issues = [issue for observation in risky
                  for issue in (observation.datos.get("issues")
                                if isinstance(observation.datos.get("issues"), list) else [])
                  if isinstance(issue, dict) and issue.get("rule") == "CONF-008"
                  and issue.get("evaluable") is True]
        if not risky or not issues:
            continue
        age = min((value for observation in risky
                   if isinstance((value := observation.datos.get("antiguedad_dias")), int)), default=None)
        candidates.append(Candidato(asset_id, risky, {
            "activo": risky[0].valor,
            "url_http": risky[0].datos.get("url_inicial"),
            "url_final": risky[0].datos.get("url_final"),
            "estado_http": risky[0].datos.get("estado_http"),
            "cadena_redireccion": risky[0].datos.get("cadena_redireccion", []),
            "respuesta_observada_en": latest_date.isoformat(),
            "referencias": sorted({reference for observation in risky
                                   for reference in observation.datos.get("referencias", [])
                                   if isinstance(reference, str)}),
            "historico": True, "potencial": True, "verificado_actual": False,
        }, nivel_evidencia="potencial", antiguedad_dias=age,
            motivo_no_confirmado="Evidencia histórica de urlscan; la redirección HTTP actual no fue verificada."))
    return candidates


# ---------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DefinicionRegla:
    codigo: str
    #: Fuentes que pueden aportar los datos de esta regla. Si NINGUNA terminó bien,
    #: la regla no se evalúa (en vez de darla por "sin hallazgos").
    requiere_fuentes: tuple[str, ...]
    #: Confianza con UNA sola fuente. Cada fuente independiente adicional suma 0.15.
    confianza_base: float
    evaluar: Callable[[Sequence[Obs], datetime], list[Candidato]]


DEFINICIONES: dict[str, DefinicionRegla] = {
    d.codigo: d
    for d in (
        DefinicionRegla("INFRA-001", ("Shodan", "SpiderFoot"), 0.70, _evaluador_puertos(PUERTOS_ADMIN_REMOTA)),
        DefinicionRegla("INFRA-002", ("Shodan", "SpiderFoot"), 0.70, _evaluador_puertos(PUERTOS_BASE_DE_DATOS)),
        DefinicionRegla("INFRA-003", ("Shodan", "SpiderFoot"), 0.50, _evaluar_cve),
        DefinicionRegla("CONF-001", ("crt.sh",), 0.90, _evaluar_cert_expirado),
        DefinicionRegla("CONF-002", ("crt.sh",), 0.90, _evaluar_cert_por_expirar),
        DefinicionRegla("CONF-003", ("SpiderFoot",), 0.85, _evaluar_postura_dns),
        DefinicionRegla("CONF-004", ("SpiderFoot",), 0.65, _evaluar_cabeceras_urlscan),
        DefinicionRegla("IDEN-003", ("theHarvester", "SpiderFoot"), 0.80, _evaluar_correos),
        # CONF-006 intentionally has no evaluator: CT and urlscan expose historical
        # certificate metadata, not a trustworthy current TLS validation failure.
        DefinicionRegla("CONF-007", ("SpiderFoot",), 0.65, _evaluar_cert_proximo_urlscan),
        DefinicionRegla("CONF-008", ("SpiderFoot",), 0.65, _evaluar_http_sin_https_urlscan),
    )
}
