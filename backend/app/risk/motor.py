"""Motor de riesgo: observaciones -> hallazgos -> puntajes.

Es una función pura (no toca la red ni la base de datos): mismas observaciones
y mismo catálogo de reglas dan siempre el mismo resultado. Eso la hace fácil
de probar y de explicar.

Puntaje
-------
Cada hallazgo aporta  peso * (0.6 + 0.4 * confianza)  puntos de riesgo.
Los aportes se combinan con rendimientos decrecientes (nunca pasan de 100):

    categoria = 100 * (1 - Π (1 - aporte_i / 100))
    global    = 100 * (1 - Π (1 - categoria_j / 100))

Calibración: `peso` y `severidad` viven en la tabla `reglas_riesgo`; se ajustan
con un UPDATE, sin tocar este código.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from app.risk.modelos import Candidato, Hallazgo, Obs, Puntaje, Regla, ResultadoRiesgo
from app.risk.reglas import DEFINICIONES

log = logging.getLogger(__name__)

VERSION_MOTOR = "1.3.2"
CATEGORIAS = ("infraestructura", "identidad_digital", "configuracion", "fuga_de_datos")
#: Qué fuente se registra como "principal" en hallazgos.fuente_id cuando varias coinciden.
PRIORIDAD_FUENTE = ("Web", "Shodan", "crt.sh", "SpiderFoot", "theHarvester")
BONO_POR_FUENTE_ADICIONAL = 0.15
FACTOR_CONFIANZA = (0.6, 0.4)  # aporte = peso * (0.6 + 0.4 * confianza)
ESTADOS_VIGENTES = frozenset({"abierto", "nuevo", "revisado", "aceptado"})


def combinar_riesgos(valores: Iterable[float]) -> float:
    """100 * (1 - Π(1 - v/100)): suma con rendimientos decrecientes, acotada a [0, 100]."""
    restante = 1.0
    for v in valores:
        restante *= 1.0 - min(max(v, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - restante)


def calcular_confianza(base: float, n_fuentes: int) -> float:
    return round(min(0.99, base + BONO_POR_FUENTE_ADICIONAL * (max(n_fuentes, 1) - 1)), 2)


def aporte_hallazgo(peso: int, confianza: float) -> float:
    return peso * (FACTOR_CONFIANZA[0] + FACTOR_CONFIANZA[1] * confianza)


def puntuar_hallazgos(hallazgos: Sequence[Hallazgo], reglas: Sequence[Regla]) -> dict[str, int]:
    """Calcula el riesgo de hallazgos vigentes, sin contar dos veces el mismo activo y regla."""
    pesos = {regla.id: regla.peso for regla in reglas if regla.esta_activa}
    aportes: dict[str, list[float]] = {categoria: [] for categoria in CATEGORIAS}
    vistos: set[tuple[str, str]] = set()
    for hallazgo in hallazgos:
        if hallazgo.nivel_evidencia != "confirmada":
            continue
        clave = (hallazgo.activo_id, hallazgo.regla_id)
        if clave in vistos or hallazgo.regla_id not in pesos or hallazgo.categoria not in aportes:
            continue
        vistos.add(clave)
        aportes[hallazgo.categoria].append(aporte_hallazgo(pesos[hallazgo.regla_id], hallazgo.confianza))
    categorias = {categoria: round(combinar_riesgos(valores)) for categoria, valores in aportes.items()}
    return {"puntaje_global": round(combinar_riesgos(categorias.values())), **categorias}


def _factor_antiguedad(days: int | None, pending_revalidation: bool) -> float:
    """Decaimiento informativo con vida media de 180 días; no altera el Risk Score."""
    factor = 0.5 if days is None else max(0.1, math.pow(0.5, max(days, 0) / 180))
    return round(factor * (0.5 if pending_revalidation else 1.0), 4)


def calcular_riesgo_potencial(hallazgos: Sequence[Hallazgo], reglas: Sequence[Regla]) -> dict[str, object]:
    """Indicador separado: solo señales explícitamente potenciales, vigentes y atribuidas."""
    catalog = {rule.id: rule for rule in reglas}
    contributions: dict[tuple[str, str], dict[str, object]] = {}
    for finding in hallazgos:
        rule = catalog.get(finding.regla_id)
        evidence = finding.evidencia or {}
        if (finding.nivel_evidencia != "potencial" or finding.estado not in ESTADOS_VIGENTES
                or rule is None or rule.categoria not in CATEGORIAS
                or not finding.activo_id or not finding.fuente_id
                or evidence.get("retirado_del_riesgo") is True):
            continue
        age = finding.antiguedad_dias
        factor = _factor_antiguedad(age, evidence.get("pendiente_revalidacion") is True)
        contribution = round(rule.peso * min(max(finding.confianza, 0.0), 1.0) * factor, 2)
        item = {
            "activo_id": finding.activo_id, "regla": rule.codigo,
            "regla_activa": rule.esta_activa, "categoria": rule.categoria,
            "severidad": rule.severidad, "confianza": finding.confianza,
            "antiguedad_dias": age, "factor_antiguedad": factor,
            "aporte_potencial": contribution,
        }
        key = (finding.activo_id, finding.regla_id)
        if key not in contributions or contribution > float(contributions[key]["aporte_potencial"]):
            contributions[key] = item

    def summary(active: bool | None) -> dict[str, object]:
        selected = [item for item in contributions.values()
                    if active is None or item["regla_activa"] is active]
        categories = {
            category: round(combinar_riesgos(
                float(item["aporte_potencial"]) for item in selected if item["categoria"] == category
            )) for category in CATEGORIAS
        }
        return {
            "puntaje_global": round(combinar_riesgos(categories.values())),
            **categories,
            "hallazgos": len(selected),
            "reglas": sorted({str(item["regla"]) for item in selected}),
        }

    return {
        "version": 1,
        **summary(None),
        "reglas_activas": summary(True),
        "reglas_inactivas": summary(False),
        "contribuciones": sorted(contributions.values(), key=lambda item: (
            -float(item["aporte_potencial"]), str(item["regla"]), str(item["activo_id"])
        )),
        "formula": "peso × confianza × factor_antiguedad; vida_media=180d; pendiente_revalidacion=0.5",
    }


def _fuente_principal(observaciones: Sequence[Obs]) -> Obs:
    def prioridad(o: Obs) -> int:
        return PRIORIDAD_FUENTE.index(o.fuente) if o.fuente in PRIORIDAD_FUENTE else len(PRIORIDAD_FUENTE)

    return min(observaciones, key=prioridad)


def _hallazgo(regla: Regla, base: float, candidato: Candidato) -> Hallazgo:
    fuentes = sorted({o.fuente for o in candidato.observaciones})
    confianza = calcular_confianza(base, len(fuentes))
    ids = sorted({o.id for o in candidato.observaciones})
    aporte = round(aporte_hallazgo(regla.peso, confianza), 2)
    evidencia = {
        "regla": regla.codigo,
        "peso": regla.peso,
        "fuentes": fuentes,
        "observaciones": ids[:20],
        "detalle": candidato.detalle,
        "nivel_evidencia": candidato.nivel_evidencia,
        "antiguedad_dias": candidato.antiguedad_dias,
        "motivo_no_confirmado": candidato.motivo_no_confirmado,
    }
    if candidato.nivel_evidencia == "confirmada":
        evidencia["aporte"] = aporte
    else:
        evidencia["aporte_potencial_estimado"] = aporte
    return Hallazgo(
        activo_id=candidato.activo_id,
        regla_id=regla.id,
        regla_codigo=regla.codigo,
        fuente_id=_fuente_principal(candidato.observaciones).fuente_id,
        categoria=regla.categoria,
        severidad=regla.severidad,
        confianza=confianza,
        evidencia=evidencia,
        nivel_evidencia=candidato.nivel_evidencia,
        antiguedad_dias=candidato.antiguedad_dias,
        motivo_no_confirmado=candidato.motivo_no_confirmado,
    )


def _deduplicar_hallazgos(hallazgos: Sequence[Hallazgo]) -> list[Hallazgo]:
    """Un activo/regla aparece una vez; evidencia confirmada prevalece sobre potencial."""
    rank = {"sin_clasificar": -1, "potencial": 0, "confirmada": 1}
    unique: dict[tuple[str, str], Hallazgo] = {}
    for finding in hallazgos:
        key = (finding.activo_id, finding.regla_id)
        current = unique.get(key)
        if current is None or (rank[finding.nivel_evidencia], finding.confianza) > (
                rank[current.nivel_evidencia], current.confianza):
            unique[key] = finding
    return list(unique.values())


def evaluar_riesgo(
    observaciones: Sequence[Obs],
    reglas: Sequence[Regla],
    estado_fuentes: Mapping[str, str],
    ahora: datetime | None = None,
) -> ResultadoRiesgo:
    """Evalúa las reglas activas y calcula los puntajes.

    `estado_fuentes` es {nombre_fuente: estado} de `resultados_fuentes`. Si está
    vacío (datos ingeridos sin orquestador) se asume que todas las fuentes están
    disponibles.
    """
    ahora = ahora or datetime.now(timezone.utc)
    fuentes_ok = {n for n, e in estado_fuentes.items() if e in {"completado", "parcial"}} if estado_fuentes else None
    fuentes_faltantes = sorted(n for n, e in estado_fuentes.items() if e != "completado")

    hallazgos: list[Hallazgo] = []
    evaluadas: list[str] = []
    no_evaluadas: list[dict[str, str]] = []

    for regla in sorted(reglas, key=lambda r: r.codigo):
        definicion = DEFINICIONES.get(regla.codigo)
        if not regla.esta_activa:
            no_evaluadas.append({"codigo": regla.codigo, "motivo": "inactiva"})
            sources_available = (fuentes_ok is None or definicion is not None
                                 and bool(set(definicion.requiere_fuentes) & fuentes_ok))
            if definicion is not None and regla.categoria in CATEGORIAS and sources_available:
                for candidato in definicion.evaluar(observaciones, ahora):
                    if candidato.nivel_evidencia == "potencial":
                        hallazgos.append(_hallazgo(regla, definicion.confianza_base, candidato))
        elif definicion is None:
            no_evaluadas.append({"codigo": regla.codigo, "motivo": "sin_evaluador"})
        elif regla.categoria not in CATEGORIAS:
            log.warning("Regla %s con categoría desconocida %r", regla.codigo, regla.categoria)
            no_evaluadas.append({"codigo": regla.codigo, "motivo": "categoria_invalida"})
        elif fuentes_ok is not None and not (set(definicion.requiere_fuentes) & fuentes_ok):
            no_evaluadas.append({"codigo": regla.codigo, "motivo": "fuentes_fallidas"})
        else:
            evaluadas.append(regla.codigo)
            for candidato in definicion.evaluar(observaciones, ahora):
                hallazgos.append(_hallazgo(regla, definicion.confianza_base, candidato))

    hallazgos = _deduplicar_hallazgos(hallazgos)
    puntuacion = puntuar_hallazgos(hallazgos, reglas)
    riesgo_potencial = calcular_riesgo_potencial(hallazgos, reglas)

    total = len(reglas)
    activas = sum(regla.esta_activa for regla in reglas)
    puntaje = Puntaje(
        puntaje_global=puntuacion["puntaje_global"],
        infraestructura=puntuacion["infraestructura"],
        identidad_digital=puntuacion["identidad_digital"],
        configuracion=puntuacion["configuracion"],
        fuga_de_datos=puntuacion["fuga_de_datos"],
        es_parcial=bool(fuentes_faltantes),
        fuentes_faltantes=fuentes_faltantes,
        cobertura={
            "total_reglas": total,
            "reglas_activas": activas,
            "evaluadas": evaluadas,
            "no_evaluadas": no_evaluadas,
            "porcentaje_evaluadas": round(100 * len(evaluadas) / activas) if activas else 0,
            "riesgo_potencial": riesgo_potencial,
        },
        version_motor=VERSION_MOTOR,
    )
    return ResultadoRiesgo(hallazgos, puntaje)
