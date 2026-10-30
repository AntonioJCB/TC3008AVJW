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
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from app.risk.modelos import Candidato, Hallazgo, Obs, Puntaje, Regla, ResultadoRiesgo
from app.risk.reglas import DEFINICIONES

log = logging.getLogger(__name__)

VERSION_MOTOR = "1.0.0"
CATEGORIAS = ("infraestructura", "identidad_digital", "configuracion", "fuga_de_datos")
#: Qué fuente se registra como "principal" en hallazgos.fuente_id cuando varias coinciden.
PRIORIDAD_FUENTE = ("Shodan", "crt.sh", "SpiderFoot", "theHarvester")
BONO_POR_FUENTE_ADICIONAL = 0.15
FACTOR_CONFIANZA = (0.6, 0.4)  # aporte = peso * (0.6 + 0.4 * confianza)


def combinar_riesgos(valores: Iterable[float]) -> float:
    """100 * (1 - Π(1 - v/100)): suma con rendimientos decrecientes, acotada a [0, 100]."""
    restante = 1.0
    for v in valores:
        restante *= 1.0 - min(max(v, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - restante)


def calcular_confianza(base: float, n_fuentes: int) -> float:
    return round(min(0.99, base + BONO_POR_FUENTE_ADICIONAL * (max(n_fuentes, 1) - 1)), 2)


def _aporte(peso: int, confianza: float) -> float:
    return peso * (FACTOR_CONFIANZA[0] + FACTOR_CONFIANZA[1] * confianza)


def _fuente_principal(observaciones: Sequence[Obs]) -> Obs:
    def prioridad(o: Obs) -> int:
        return PRIORIDAD_FUENTE.index(o.fuente) if o.fuente in PRIORIDAD_FUENTE else len(PRIORIDAD_FUENTE)

    return min(observaciones, key=prioridad)


def _hallazgo(regla: Regla, base: float, candidato: Candidato) -> Hallazgo:
    fuentes = sorted({o.fuente for o in candidato.observaciones})
    confianza = calcular_confianza(base, len(fuentes))
    ids = sorted({o.id for o in candidato.observaciones})
    return Hallazgo(
        activo_id=candidato.activo_id,
        regla_id=regla.id,
        regla_codigo=regla.codigo,
        fuente_id=_fuente_principal(candidato.observaciones).fuente_id,
        categoria=regla.categoria,
        severidad=regla.severidad,
        confianza=confianza,
        evidencia={
            "regla": regla.codigo,
            "peso": regla.peso,
            "aporte": round(_aporte(regla.peso, confianza), 2),
            "fuentes": fuentes,
            "observaciones": ids[:20],
            "detalle": candidato.detalle,
        },
    )


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
    fuentes_ok = {n for n, e in estado_fuentes.items() if e == "completado"} if estado_fuentes else None
    fuentes_faltantes = sorted(n for n, e in estado_fuentes.items() if e != "completado")

    hallazgos: list[Hallazgo] = []
    evaluadas: list[str] = []
    no_evaluadas: list[dict[str, str]] = []

    for regla in sorted(reglas, key=lambda r: r.codigo):
        definicion = DEFINICIONES.get(regla.codigo)
        if not regla.esta_activa:
            no_evaluadas.append({"codigo": regla.codigo, "motivo": "inactiva"})
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

    pesos = {r.id: r.peso for r in reglas}
    aportes: dict[str, list[float]] = {c: [] for c in CATEGORIAS}
    for h in hallazgos:
        aportes[h.categoria].append(_aporte(pesos[h.regla_id], h.confianza))
    por_categoria = {c: round(combinar_riesgos(v)) for c, v in aportes.items()}
    global_ = round(combinar_riesgos(por_categoria.values()))

    total = len(reglas)
    puntaje = Puntaje(
        puntaje_global=global_,
        infraestructura=por_categoria["infraestructura"],
        identidad_digital=por_categoria["identidad_digital"],
        configuracion=por_categoria["configuracion"],
        fuga_de_datos=por_categoria["fuga_de_datos"],
        es_parcial=bool(fuentes_faltantes),
        fuentes_faltantes=fuentes_faltantes,
        cobertura={
            "total_reglas": total,
            "evaluadas": evaluadas,
            "no_evaluadas": no_evaluadas,
            "porcentaje_evaluadas": round(100 * len(evaluadas) / total) if total else 0,
        },
        version_motor=VERSION_MOTOR,
    )
    return ResultadoRiesgo(hallazgos, puntaje)
