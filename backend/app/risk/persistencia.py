"""Lectura de observaciones y escritura de hallazgos/puntajes en Supabase."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from app.risk.modelos import Obs, Regla, ResultadoRiesgo
from app.risk.motor import evaluar_riesgo

PAGINA = 1000
ORDEN_SEVERIDAD = {"critica": 0, "alta": 1, "media": 2, "baja": 3}


def _paginar(construir: Callable[[int, int], Any]) -> list[dict[str, Any]]:
    """PostgREST devuelve como máximo ~1000 filas por petición: se pide por páginas."""
    filas: list[dict[str, Any]] = []
    inicio = 0
    while True:
        pagina = construir(inicio, inicio + PAGINA - 1).execute().data or []
        filas.extend(pagina)
        if len(pagina) < PAGINA:
            return filas
        inicio += PAGINA


def cargar_observaciones(client: Any, scan_id: str) -> list[Obs]:
    filas = _paginar(
        lambda a, b: client.table("observaciones")
        .select("id, activo_id, atributo, datos, observado_en, fuente_id, activos(tipo, valor), fuentes_osint(nombre)")
        .eq("escaneo_id", scan_id)
        .order("id")
        .range(a, b)
    )
    return [
        Obs(
            id=str(f["id"]),
            activo_id=str(f["activo_id"]),
            tipo=f["activos"]["tipo"],
            valor=f["activos"]["valor"],
            atributo=f["atributo"],
            datos=f.get("datos") or {},
            fuente=f["fuentes_osint"]["nombre"],
            fuente_id=str(f["fuente_id"]),
            observado_en=f.get("observado_en"),
        )
        for f in filas
        if f.get("activos") and f.get("fuentes_osint")
    ]


def cargar_reglas(client: Any) -> list[Regla]:
    filas = client.table("reglas_riesgo").select("id, codigo, nombre, categoria, severidad, peso, esta_activa").execute().data or []
    return [
        Regla(str(f["id"]), f["codigo"], f["nombre"], f["categoria"], f["severidad"], int(f["peso"]), bool(f["esta_activa"]))
        for f in filas
    ]


def cargar_estado_fuentes(client: Any, scan_id: str) -> dict[str, str]:
    filas = (
        client.table("resultados_fuentes").select("estado, fuentes_osint(nombre)").eq("escaneo_id", scan_id).execute().data
        or []
    )
    return {f["fuentes_osint"]["nombre"]: f["estado"] for f in filas if f.get("fuentes_osint")}


def calcular_y_guardar(client: Any, scan_id: str, ahora: datetime | None = None) -> ResultadoRiesgo:
    """Calcula el riesgo de un escaneo y lo guarda de forma atómica (RPC guardar_riesgo)."""
    resultado = evaluar_riesgo(
        cargar_observaciones(client, scan_id), cargar_reglas(client), cargar_estado_fuentes(client, scan_id), ahora
    )
    client.rpc(
        "guardar_riesgo",
        {
            "p_escaneo_id": scan_id,
            "p_hallazgos": [h.como_dict() for h in resultado.hallazgos],
            "p_puntaje": resultado.puntaje.como_dict(),
        },
    ).execute()
    return resultado


def leer_riesgo(client: Any, scan_id: str) -> dict[str, Any] | None:
    filas = (
        client.table("puntajes_riesgo")
        .select(
            "puntaje_global, infraestructura, identidad_digital, configuracion, fuga_de_datos, "
            "es_parcial, fuentes_faltantes, cobertura, version_motor, calculado_en"
        )
        .eq("escaneo_id", scan_id)
        .limit(1)
        .execute()
        .data
    )
    return filas[0] if filas else None


def leer_hallazgos(client: Any, scan_id: str) -> list[dict[str, Any]]:
    filas = _paginar(
        lambda a, b: client.table("hallazgos")
        .select(
            "id, categoria, severidad, confianza, estado, evidencia, "
            "reglas_riesgo(codigo, nombre, descripcion), activos(tipo, valor), fuentes_osint(nombre)"
        )
        .eq("escaneo_id", scan_id)
        .order("id")
        .range(a, b)
    )
    return sorted(
        filas,
        key=lambda f: (ORDEN_SEVERIDAD.get(f["severidad"], 9), -float(f["confianza"] or 0), (f.get("reglas_riesgo") or {}).get("codigo", "")),
    )
