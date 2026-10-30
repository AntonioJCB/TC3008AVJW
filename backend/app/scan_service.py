"""Ciclo de vida de un escaneo OSINT.

  pendiente -> ejecutando -> completado | incompleto | fallido

Un escaneo corre las cuatro fuentes en paralelo. Cada fuente se guarda apenas
termina (no espera a la más lenta) y, si falla, las demás siguen. Al final:
  completado : todas las fuentes terminaron bien
  incompleto : al menos una falló y al menos una terminó bien
  fallido    : ninguna terminó bien
Después se calcula el riesgo con lo que sí llegó (marcado como parcial si
faltó alguna fuente).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool
from supabase import Client

from app.ingestion import ingestar_resultado
from app.orchestrators import OrchestratorSettings, Runner, run_all
from app.risk.persistencia import calcular_y_guardar
from app.settings import Settings

logger = logging.getLogger(__name__)

SOURCE_NAMES = ("crt.sh", "Shodan", "theHarvester", "SpiderFoot")

PENDIENTE = "pendiente"
EJECUTANDO = "ejecutando"
COMPLETADO = "completado"
INCOMPLETO = "incompleto"
FALLIDO = "fallido"
ESTADOS_FINALES = (COMPLETADO, INCOMPLETO, FALLIDO)

INTERRUMPIDO = "Interrumpido: el servidor se reinició o el escaneo superó el tiempo máximo"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execute(query: Any) -> Any:
    """Ejecuta una consulta de supabase-py. Devuelve None si no hay filas (maybe_single)."""
    try:
        response = query.execute()
    except Exception as error:
        logger.exception("Falló una consulta a Supabase")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo consultar o actualizar el estado del escaneo en Supabase",
        ) from error
    # maybe_single() devuelve None (no una respuesta) cuando no hay filas.
    return None if response is None else response.data


def audit(
    client: Client,
    *,
    user_id: str | None,
    organization_id: str,
    action: str,
    scan_id: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Registra en bitacora_auditoria quién hizo qué. Nunca interrumpe el flujo principal."""
    try:
        client.table("bitacora_auditoria").insert(
            {
                "usuario_id": user_id,
                "organizacion_id": organization_id,
                "accion": action,
                "entidad": "escaneos",
                "entidad_id": scan_id,
                "detalle": detail or {},
            }
        ).execute()
    except Exception:
        logger.warning("No se pudo registrar %s en la bitácora de auditoría", action, exc_info=True)


# ---------------------------------------------------------------------
# Estado y mensajes
# ---------------------------------------------------------------------


def compute_scan_state(results: Mapping[str, Mapping[str, Any]]) -> str:
    """Estado final a partir del resultado de cada fuente. Una fuente ausente cuenta como fallida."""
    completed = sum(1 for name in SOURCE_NAMES if results.get(name, {}).get("estado") == COMPLETADO)
    if completed == len(SOURCE_NAMES):
        return COMPLETADO
    return FALLIDO if completed == 0 else INCOMPLETO


def scan_message(scan_state: str, results: Mapping[str, Mapping[str, Any]]) -> str:
    """Frase para el usuario: qué falló y qué no."""
    ok = [n for n in SOURCE_NAMES if results.get(n, {}).get("estado") == COMPLETADO]
    failed = [n for n in SOURCE_NAMES if results.get(n, {}).get("estado") == "fallido"]

    def razon(name: str) -> str:
        error = str(results[name].get("error") or "").strip()
        return f"{name} ({error[:120]})" if error else name

    if scan_state == PENDIENTE:
        return "El escaneo está pendiente de ejecución."
    if scan_state == EJECUTANDO:
        return f"El escaneo está en curso: {len(ok) + len(failed)} de {len(SOURCE_NAMES)} fuentes han terminado."
    if scan_state == COMPLETADO:
        return f"Escaneo completo: las {len(SOURCE_NAMES)} fuentes terminaron correctamente."
    if scan_state == INCOMPLETO:
        return (
            f"Escaneo incompleto. Fallaron: {', '.join(razon(n) for n in failed)}. "
            f"Terminaron correctamente: {', '.join(ok)}."
        )
    if scan_state == FALLIDO:
        return f"Escaneo fallido: ninguna fuente terminó correctamente. {', '.join(razon(n) for n in failed)}."
    return f"Escaneo {scan_state}."


# ---------------------------------------------------------------------
# Operaciones sobre la base de datos
# ---------------------------------------------------------------------


def orchestrator_settings(settings: Settings) -> OrchestratorSettings:
    return OrchestratorSettings(
        shodan_api_key=settings.shodan_api_key,
        theharvester_bin=settings.theharvester_bin,
        theharvester_sources=settings.theharvester_sources,
        spiderfoot_url=settings.spiderfoot_url,
        request_timeout_seconds=settings.request_timeout_seconds,
        process_timeout_seconds=settings.process_timeout_seconds,
        spiderfoot_timeout_seconds=settings.spiderfoot_timeout_seconds,
        spiderfoot_poll_seconds=settings.spiderfoot_poll_seconds,
        crtsh_retries=settings.crtsh_retries,
        shodan_max_ips=settings.shodan_max_ips,
        shodan_pause_seconds=settings.shodan_pause_seconds,
    )


def _source_ids(client: Client) -> dict[str, str]:
    rows = _execute(client.table("fuentes_osint").select("id, nombre").in_("nombre", list(SOURCE_NAMES))) or []
    found = {row["nombre"]: row["id"] for row in rows}
    missing = set(SOURCE_NAMES) - found.keys()
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Faltan fuentes en el catálogo de Supabase: {', '.join(sorted(missing))}",
        )
    return found


def _start_scan(client: Client, scan_id: str, source_ids: dict[str, str]) -> None:
    """Reclama el escaneo (solo si sigue 'pendiente') y deja las fuentes 'ejecutando'."""
    now = _now()
    claimed = _execute(
        client.table("escaneos")
        .update({"estado": EJECUTANDO, "iniciado_en": now})
        .eq("id", scan_id)
        .eq("estado", PENDIENTE)
    )
    if not claimed:
        raise HTTPException(status_code=409, detail="El escaneo ya fue iniciado por otra solicitud")
    rows = [
        {"escaneo_id": scan_id, "fuente_id": source_ids[name], "estado": EJECUTANDO, "iniciado_en": now}
        for name in SOURCE_NAMES
    ]
    _execute(client.table("resultados_fuentes").upsert(rows, on_conflict="escaneo_id,fuente_id"))


def _persist_source(
    client: Client,
    organization_id: str,
    scan_id: str,
    source_id: str,
    source_name: str,
    domain: str,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    """Normaliza y guarda el resultado de UNA fuente y registra su estado."""
    summary: dict[str, Any] = {
        "resultado_crudo_id": None,
        "ya_procesado": False,
        "observaciones_generadas": 0,
        "activos_nuevos": 0,
        "activos_existentes": 0,
        "observaciones_nuevas": 0,
        "observaciones_duplicadas": 0,
        "descartadas": {},
    }
    source_state = outcome["estado"]
    error = outcome.get("error")
    if source_state == "completado":
        try:
            summary = ingestar_resultado(
                client,
                organization_id=organization_id,
                scan_id=scan_id,
                source_id=source_id,
                source=source_name,
                raw=outcome["contenido"],
                domain=domain,
                ips_in_scope=outcome.get("ips_en_alcance") or None,
            )
        except Exception:
            logger.exception("No se pudo normalizar o guardar el resultado de %s", source_name)
            source_state = "fallido"
            error = "No se pudo normalizar o guardar el resultado de esta fuente"
    status_data = {**summary, "estado": source_state, "error": error, "finalizado_en": _now()}
    _execute(
        client.table("resultados_fuentes")
        .update(status_data)
        .eq("escaneo_id", scan_id)
        .eq("fuente_id", source_id)
    )
    return status_data


def _finish_scan(client: Client, scan_id: str, scan_state: str) -> None:
    _execute(client.table("escaneos").update({"estado": scan_state, "finalizado_en": _now()}).eq("id", scan_id))


# ---------------------------------------------------------------------
# Ejecución en segundo plano
# ---------------------------------------------------------------------


async def run_scan_job(
    client: Client,
    settings: Settings,
    scan: dict[str, Any],
    source_ids: dict[str, str],
    domain: str,
    runners: dict[str, Runner] | None = None,
) -> str:
    """Corre las fuentes, guarda cada una al terminar, cierra el escaneo y calcula el riesgo."""
    scan_id = scan["id"]
    organization_id = scan["organizacion_id"]
    persisted: dict[str, dict[str, Any]] = {}

    async def on_result(name: str, outcome: dict[str, Any]) -> None:
        try:
            persisted[name] = await run_in_threadpool(
                _persist_source, client, organization_id, scan_id, source_ids[name], name, domain, outcome
            )
        except Exception:
            logger.exception("No se pudo persistir el resultado de %s", name)
            persisted[name] = {"estado": "fallido", "error": "No se pudo persistir el resultado de esta fuente"}

    try:
        await run_all(
            domain,
            orchestrator_settings(settings),
            runners=runners,
            on_result=on_result,
            timeout_seconds=settings.scan_timeout_seconds,
        )
    except Exception:
        logger.exception("Falló la ejecución de las fuentes del escaneo %s", scan_id)

    scan_state = compute_scan_state(persisted)
    await run_in_threadpool(_finish_scan, client, scan_id, scan_state)
    logger.info("Escaneo %s: %s", scan_id, scan_message(scan_state, persisted))
    await run_in_threadpool(
        audit,
        client,
        user_id=scan.get("solicitado_por"),
        organization_id=organization_id,
        action="escaneo_finalizado",
        scan_id=scan_id,
        detail={
            "estado": scan_state,
            "fuentes_ok": [n for n in SOURCE_NAMES if persisted.get(n, {}).get("estado") == COMPLETADO],
            "fuentes_fallidas": {
                n: persisted.get(n, {}).get("error") or "sin resultado"
                for n in SOURCE_NAMES
                if persisted.get(n, {}).get("estado") != COMPLETADO
            },
        },
    )

    try:
        await run_in_threadpool(calcular_y_guardar, client, scan_id)
    except Exception:
        # El escaneo ya quedó cerrado; el riesgo se puede recalcular con
        # POST /api/escaneos/{id}/riesgo/recalcular.
        logger.exception("No se pudo calcular el riesgo del escaneo %s", scan_id)
    return scan_state


def reap_stuck_scans(client: Client, max_age_seconds: float) -> int:
    """Cierra escaneos que quedaron 'ejecutando' (p. ej. el servidor se reinició a mitad).

    Las tareas en segundo plano viven en la memoria del proceso: si este se cae,
    el escaneo no avanzaría nunca. Se llama al arrancar la API.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
    stuck = _execute(client.table("escaneos").select("id").eq("estado", EJECUTANDO).lt("iniciado_en", cutoff)) or []
    for row in stuck:
        scan_id = row["id"]
        _execute(
            client.table("resultados_fuentes")
            .update({"estado": "fallido", "error": INTERRUMPIDO, "finalizado_en": _now()})
            .eq("escaneo_id", scan_id)
            .in_("estado", ["pendiente", EJECUTANDO])
        )
        rows = _execute(
            client.table("resultados_fuentes").select("estado, fuentes_osint(nombre)").eq("escaneo_id", scan_id)
        ) or []
        results = {r["fuentes_osint"]["nombre"]: {"estado": r["estado"]} for r in rows if r.get("fuentes_osint")}
        _finish_scan(client, scan_id, compute_scan_state(results))
        logger.warning("Escaneo %s cerrado por estar interrumpido", scan_id)
    return len(stuck)
