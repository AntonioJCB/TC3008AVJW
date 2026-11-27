"""Arma el contexto de un escaneo para el asistente de IA.

Solo lee datos ya procesados (riesgo, hallazgos, estado de fuentes). La IA
explica; el puntaje lo calcula el motor de riesgo.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping, Sequence

from app.risk.persistencia import cargar_estado_fuentes, leer_hallazgos, leer_riesgo
from app.scan_service import COMPLETADO, INCOMPLETO

MAX_HALLAZGOS = 40
MAX_CAMPO = 200
MAX_DETALLE = 300
CATEGORIAS = (
    ("infraestructura", "Infraestructura"),
    ("identidad_digital", "Identidad digital"),
    ("configuracion", "Configuración"),
    ("fuga_de_datos", "Fuga de datos"),
)


def _texto(valor: Any, limite: int = MAX_CAMPO) -> str:
    """Una línea corta. Quita < y > para que los datos no puedan cerrar etiquetas del prompt."""
    texto = " ".join(str(valor if valor is not None else "").split())
    texto = texto.replace("<", "‹").replace(">", "›")
    return texto[: limite - 1] + "…" if len(texto) > limite else texto

def _resumen_cobertura(cobertura: Any) -> list[str]:
    """Qué reglas se evaluaron y qué activos no se analizaron. Un 0 sin reglas evaluadas es 'no evaluado'."""
    if not isinstance(cobertura, Mapping):
        return []
    lineas = ["Cobertura del análisis:"]
    total, activas = cobertura.get("total_reglas"), cobertura.get("reglas_activas")
    if total is not None and activas is not None:
        lineas.append(f"- Reglas de riesgo activas: {activas} de {total}.")

    def _por_prefijo(reglas: Any) -> str:
        cuenta = Counter(
            str(r.get("codigo") if isinstance(r, Mapping) else r).split("-")[0] for r in reglas or []
        )
        return ", ".join(f"{_texto(k, 20)}: {v}" for k, v in sorted(cuenta.items())) or "ninguna"

    lineas.append(f"- Reglas evaluadas (prefijo: cantidad): {_por_prefijo(cobertura.get('evaluadas'))}.")
    lineas.append(f"- Reglas sin evaluar (prefijo: cantidad): {_por_prefijo(cobertura.get('no_evaluadas'))}.")

    infra = cobertura.get("infraestructura")
    if isinstance(infra, Mapping):
        activos = [a for a in infra.get("activos") or [] if isinstance(a, Mapping)]
        if activos:
            analizados = sum(1 for a in activos if a.get("incluido"))
            lineas.append(
                f"- Activos de infraestructura vistos: {len(activos)}; "
                f"analizados con las fuentes: {analizados}; no analizados: {len(activos) - analizados}."
            )
            motivos = Counter(_texto(a.get("motivo"), 120) for a in activos if not a.get("incluido") and a.get("motivo"))
            for motivo, n in motivos.most_common(5):
                lineas.append(f"  · {n} sin analizar: {motivo}")
        if infra.get("cobertura_incompleta"):
            lineas.append("- La cobertura de infraestructura está marcada como incompleta.")
    return lineas

def construir_contexto(
    *,
    dominio: str | None,
    estado: str | None,
    finalizado_en: str | None,
    riesgo: Mapping[str, Any] | None,
    hallazgos: Sequence[Mapping[str, Any]],
    estado_fuentes: Mapping[str, str],
) -> str:
    lineas = [
        f"Dominio analizado: {_texto(dominio)}",
        f"Estado del escaneo: {_texto(estado, 30)}",
    ]
    if finalizado_en:
        lineas.append(f"Finalizado en: {_texto(finalizado_en, 40)}")
    if estado_fuentes:
        lineas.append(
            "Estado de las fuentes: "
            + ", ".join(f"{_texto(n, 60)}={_texto(e, 30)}" for n, e in sorted(estado_fuentes.items()))
        )

    lineas.append("")
    if riesgo:
        lineas.append("Riesgo (0 a 100, mayor = más riesgo):")
        lineas.append(f"- Global: {riesgo.get('puntaje_global')}")
        for clave, nombre in CATEGORIAS:
            lineas.append(f"- {nombre}: {riesgo.get(clave)}")
        if riesgo.get("es_parcial"):
            faltantes = ", ".join(_texto(f, 60) for f in riesgo.get("fuentes_faltantes") or [])
            if faltantes:
                lineas.append(
                    f"- AVISO: puntaje parcial, no se obtuvieron datos de: {faltantes}. Puede estar subestimado."
                )
            else:
                lineas.append(
                    "- AVISO: puntaje parcial porque la cobertura del análisis es incompleta "
                    "(ver Cobertura del análisis). Puede estar subestimado."
                )
        cobertura = _resumen_cobertura(riesgo.get("cobertura"))
        if cobertura:
            lineas.append("")
            lineas.extend(cobertura)
    else:
        lineas.append("Riesgo: aún no calculado para este escaneo.")

    lineas.append("")
    conteo = Counter(h.get("severidad") for h in hallazgos)
    resumen = ", ".join(f"{s}: {conteo.get(s, 0)}" for s in ("critica", "alta", "media", "baja"))
    lineas.append(f"Hallazgos: {len(hallazgos)} en total ({resumen})")

    mostrados = list(hallazgos)[:MAX_HALLAZGOS]
    for i, h in enumerate(mostrados, 1):
        regla = h.get("reglas_riesgo") or {}
        activo = h.get("activos") or {}
        evidencia = h.get("evidencia") or {}
        fuentes = evidencia.get("fuentes") or [(h.get("fuentes_osint") or {}).get("nombre")]
        lineas.append(
            f"{i}. [{_texto(h.get('severidad'), 20)}] "
            f"{_texto(regla.get('nombre') or regla.get('codigo') or 'Sin regla')} "
            f"| categoría: {_texto(h.get('categoria'), 40)} "
            f"| activo: {_texto(activo.get('tipo'), 30)} {_texto(activo.get('valor'))} "
            f"| confianza: {float(h.get('confianza') or 0):.2f} "
            f"| fuentes: {', '.join(_texto(f, 40) for f in fuentes if f)}"
        )
        if regla.get("descripcion"):
            lineas.append(f"   Qué significa: {_texto(regla['descripcion'])}")
        if evidencia.get("detalle"):
            detalle = json.dumps(evidencia["detalle"], ensure_ascii=False, default=str)
            lineas.append(f"   Detalle: {_texto(detalle, MAX_DETALLE)}")
    if len(hallazgos) > len(mostrados):
        lineas.append(f"... y {len(hallazgos) - len(mostrados)} hallazgos menos graves no listados.")
    return "\n".join(lineas)


def escaneo_mas_reciente(client: Any, organizacion_id: str) -> dict[str, Any] | None:
    """Último escaneo terminado (completado o incompleto) de la organización."""
    filas = (
        client.table("escaneos")
        .select("id, estado, iniciado_en, finalizado_en")
        .eq("organizacion_id", organizacion_id)
        .in_("estado", [COMPLETADO, INCOMPLETO])
        .order("finalizado_en", desc=True)
        .limit(1)
        .execute()
        .data
    )
    return filas[0] if filas else None


def cargar_contexto(client: Any, escaneo: Mapping[str, Any], dominio: str | None) -> str:
    """Lee de Supabase y arma el texto. Quien llama debe haber validado que el escaneo es de su organización."""
    scan_id = str(escaneo["id"])
    return construir_contexto(
        dominio=dominio,
        estado=escaneo.get("estado"),
        finalizado_en=escaneo.get("finalizado_en"),
        riesgo=leer_riesgo(client, scan_id),
        hallazgos=leer_hallazgos(client, scan_id),
        estado_fuentes=cargar_estado_fuentes(client, scan_id),
    )