"""Evaluadores de reglas de riesgo.

Cada regla de `reglas_riesgo` (identificada por `codigo`) tiene aquí una
función que decide, a partir de las observaciones, qué activos la cumplen.
La base de datos define el CATÁLOGO (nombre, severidad, peso); este archivo
define la LÓGICA. Una regla del catálogo sin evaluador aquí se reporta como
"sin_evaluador" en la cobertura, nunca se da por cumplida ni por descartada.

Con las cuatro herramientas actuales solo se pueden evaluar 6 de las 16 reglas
del seed. El resto necesita otras fuentes (DNS, HIBP, GitHub...).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Sequence

from app.osint_normalization import parsear_servicio
from app.risk.modelos import Candidato, Obs

# Un certificado que expiró hace más de esto probablemente es de un host abandonado
# (crt.sh lista TODOS los certificados históricos): se ignora para no generar ruido.
VENTANA_EXPIRADO_DIAS = 90
DIAS_POR_EXPIRAR = 30

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
    for activo_id, grupo in _agrupar(o for o in observaciones if o.atributo == "cve").items():
        cves = sorted({str(o.datos["cve"]) for o in grupo if o.datos.get("cve")})
        if not cves:
            continue
        severidades = sorted({str(o.datos["severidad_fuente"]) for o in grupo if o.datos.get("severidad_fuente")})
        candidatos.append(
            Candidato(activo_id, grupo, {"activo": grupo[0].valor, "cves": cves, "severidades_fuente": severidades})
        )
    return candidatos


# ---------------------------------------------------------------------
# CONF-001 / CONF-002: certificados TLS (a partir de Certificate Transparency)
#
# Se mira el certificado que vence más tarde para cada nombre: si incluso ese
# ya venció, el nombre no tiene ningún certificado vigente. Así los certificados
# viejos que siguen apareciendo en crt.sh no generan falsos positivos.
# ---------------------------------------------------------------------


def _vigencia_maxima(grupo: Sequence[Obs]) -> tuple[datetime, Obs] | None:
    con_fecha = [(f, o) for o in grupo if (f := _fecha(o.datos.get("valido_hasta"))) is not None]
    return max(con_fecha, key=lambda t: t[0]) if con_fecha else None


def _evaluar_cert_expirado(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    candidatos: list[Candidato] = []
    for activo_id, grupo in _agrupar(o for o in observaciones if o.atributo == "certificado").items():
        vigencia = _vigencia_maxima(grupo)
        if vigencia is None:
            continue
        hasta, obs = vigencia
        dias = (ahora - hasta).days
        if hasta < ahora and dias <= VENTANA_EXPIRADO_DIAS:
            candidatos.append(
                Candidato(
                    activo_id,
                    [obs],
                    {
                        "activo": obs.valor, "vencio_el": hasta.isoformat(), "dias_vencido": dias,
                        "serie": obs.datos.get("serie"), "emisor": obs.datos.get("emisor"),
                    },
                )
            )
    return candidatos


def _evaluar_cert_por_expirar(observaciones: Sequence[Obs], ahora: datetime) -> list[Candidato]:
    candidatos: list[Candidato] = []
    for activo_id, grupo in _agrupar(o for o in observaciones if o.atributo == "certificado").items():
        vigencia = _vigencia_maxima(grupo)
        if vigencia is None:
            continue
        hasta, obs = vigencia
        if ahora <= hasta <= ahora + timedelta(days=DIAS_POR_EXPIRAR):
            candidatos.append(
                Candidato(
                    activo_id,
                    [obs],
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
        DefinicionRegla("IDEN-003", ("theHarvester", "SpiderFoot"), 0.80, _evaluar_correos),
    )
}
