"""Ciclo de vida de un escaneo OSINT.

  pendiente -> ejecutando -> completado | incompleto | fallido

Un escaneo corre las fuentes OSINT pasivas activas en paralelo. Cada fuente se guarda apenas
termina (no espera a la más lenta) y, si falla, las demás siguen. Al final:
  completado : todas las fuentes terminaron bien
  incompleto : al menos una falló y al menos una terminó bien
  fallido    : ninguna terminó bien
Después se calcula el riesgo con lo que sí llegó (marcado como parcial si
faltó alguna fuente).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool
from httpx import TransportError
from postgrest.exceptions import APIError
from supabase import Client

from app.ingestion import ingestar_resultado
from app.orchestrators import OrchestratorSettings, Runner, run_all
from app.risk.persistencia import calcular_y_guardar
from app.settings import Settings
from app.source_policy import (
    ACTIVE_SOURCES,
    CRTSH_DISABLED_REASON,
    DISABLED_SOURCE_STATE,
    is_disabled_source_result,
)
from app.scan_report import inventory, build_coverage

logger = logging.getLogger(__name__)

SOURCE_NAMES = ACTIVE_SOURCES

PENDIENTE = "pendiente"
EJECUTANDO = "ejecutando"
COMPLETADO = "completado"
INCOMPLETO = "incompleto"
FALLIDO = "fallido"
CANCELADO = "cancelado"
ESTADOS_FINALES = (COMPLETADO, INCOMPLETO, FALLIDO, CANCELADO)

INTERRUMPIDO = "Interrumpido: el servidor se reinició o el escaneo superó el tiempo máximo"
DETENIDO = "Detenido por el usuario"


@dataclass
class ScanControl:
    cancel_requested: asyncio.Event = field(default_factory=asyncio.Event)
    persistence_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


_active_scans: dict[str, ScanControl] = {}


def register_scan_control(scan_id: str) -> None:
    _active_scans[scan_id] = ScanControl()


def scan_job_active(scan_id: str) -> bool:
    return scan_id in _active_scans


async def calculate_risk_with_retry(
    client: Client, scan_id: str, *, attempts: int = 4, delay_seconds: float = 1.0, report: dict | None = None,
) -> None:
    """Reintenta cortes temporales de red sin ocultar errores permanentes del motor."""
    for attempt in range(attempts):
        try:
            await run_in_threadpool(calcular_y_guardar, client, scan_id, **({"report": report} if report is not None else {}))
            return
        except TransportError:
            if attempt + 1 == attempts:
                raise
            wait = delay_seconds * 2 ** attempt
            logger.warning("Supabase no respondió al calcular el riesgo de %s; reintento %s/%s en %.1f s", scan_id, attempt + 2, attempts, wait)
            await asyncio.sleep(wait)


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
    enabled = [name for name in SOURCE_NAMES if not is_disabled_source_result(
        results.get(name, {}).get("estado"), results.get(name, {}).get("error")
    )]
    completed = sum(1 for name in enabled if results.get(name, {}).get("estado") == COMPLETADO)
    if enabled and completed == len(enabled) and not any(results.get(name, {}).get("error") for name in enabled):
        return COMPLETADO
    return FALLIDO if completed == 0 else INCOMPLETO


def scan_message(scan_state: str, results: Mapping[str, Mapping[str, Any]]) -> str:
    """Frase para el usuario: qué falló y qué no."""
    ok = [n for n in SOURCE_NAMES if results.get(n, {}).get("estado") == COMPLETADO and not results.get(n, {}).get("error")]
    failed = [n for n in SOURCE_NAMES if results.get(n, {}).get("estado") == "fallido"]
    partial = [n for n in SOURCE_NAMES if results.get(n, {}).get("estado") == COMPLETADO and results.get(n, {}).get("error")]
    disabled = [n for n in SOURCE_NAMES if is_disabled_source_result(
        results.get(n, {}).get("estado"), results.get(n, {}).get("error")
    )]
    enabled_count = len(SOURCE_NAMES) - len(disabled)

    def razon(name: str) -> str:
        error = str(results[name].get("error") or "").strip()
        return f"{name} ({error[:120]})" if error else name

    if scan_state == PENDIENTE:
        return "El escaneo está pendiente de ejecución."
    if scan_state == EJECUTANDO:
        return f"El escaneo está en curso: {len(ok) + len(failed) + len(partial)} de {enabled_count} fuentes habilitadas han terminado."
    if scan_state == CANCELADO:
        return "Análisis detenido. Se conservaron los resultados de las fuentes que habían terminado."
    if scan_state == COMPLETADO:
        limitation = f" Deshabilitadas/no evaluadas: {', '.join(disabled)}." if disabled else ""
        return f"Consultas finalizadas: las {enabled_count} fuentes habilitadas terminaron correctamente.{limitation} Consulta el reporte para conocer la cobertura y sus limitaciones."
    if scan_state == INCOMPLETO:
        return (
            "Escaneo incompleto. "
            + (f"Fallaron: {', '.join(razon(n) for n in failed)}. " if failed else "")
            + (f"Con incidencias: {', '.join(razon(n) for n in partial)}. " if partial else "")
            + f"Terminaron correctamente: {', '.join(ok)}."
        )
    if scan_state == FALLIDO:
        return f"Escaneo fallido: ninguna fuente terminó correctamente. {', '.join(razon(n) for n in failed)}."
    return f"Escaneo {scan_state}."


# ---------------------------------------------------------------------
# Operaciones sobre la base de datos
# ---------------------------------------------------------------------


def orchestrator_settings(settings: Settings) -> OrchestratorSettings:
    return OrchestratorSettings(
        censys_pat=settings.censys_pat,
        censys_organization_id=getattr(settings, "censys_organization_id", None),
        censys_authorized_ips=getattr(settings, "censys_authorized_ips", ""),
        web_enabled=settings.web_enabled,
        theharvester_bin=settings.theharvester_bin,
        theharvester_sources=settings.theharvester_sources,
        spiderfoot_url=settings.spiderfoot_url,
        spiderfoot_modules=settings.spiderfoot_modules,
        request_timeout_seconds=settings.request_timeout_seconds,
        process_timeout_seconds=settings.process_timeout_seconds,
        spiderfoot_timeout_seconds=settings.spiderfoot_timeout_seconds,
        spiderfoot_poll_seconds=settings.spiderfoot_poll_seconds,
        crtsh_retries=settings.crtsh_retries,
        censys_max_ips=settings.censys_max_ips,
        censys_pause_seconds=settings.censys_pause_seconds,
        crtsh_timeout_seconds=settings.crtsh_timeout_seconds,
        crtsh_total_timeout_seconds=getattr(settings, "crtsh_total_timeout_seconds", 45),
        crtsh_enabled=getattr(settings, "crtsh_enabled", True),
    )


def _persist_disabled_source(
    client: Client, scan_id: str, source_id: str, reason: str,
) -> dict[str, Any]:
    """Conserva el catálogo sin simular una consulta ni exigir una migración."""
    stored = {
        "estado": PENDIENTE,
        "error": reason,
        "finalizado_en": _now(),
        "observaciones_generadas": 0,
        "activos_nuevos": 0,
        "activos_existentes": 0,
        "observaciones_nuevas": 0,
        "observaciones_duplicadas": 0,
        "descartadas": {},
    }
    _execute(
        client.table("resultados_fuentes").update(stored)
        .eq("escaneo_id", scan_id).eq("fuente_id", source_id)
    )
    return {**stored, "estado": DISABLED_SOURCE_STATE}


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
    """Inicia atómicamente; conserva compatibilidad hasta aplicar la migración SQL."""
    try:
        response = client.rpc(
            "iniciar_escaneo",
            {
                "p_escaneo_id": scan_id,
                "p_fuentes": [source_ids[name] for name in SOURCE_NAMES],
            },
        ).execute()
    except APIError as error:
        if error.code != "PGRST202":
            raise HTTPException(status_code=502, detail="No se pudo iniciar el escaneo") from error
        logger.warning("Falta la migración iniciar_escaneo; se usa el inicio anterior")
        _start_scan_legacy(client, scan_id, source_ids)
        return
    except Exception as error:
        raise HTTPException(status_code=502, detail="No se pudo iniciar el escaneo") from error

    if response is None or response.data is not True:
        raise HTTPException(
            status_code=409,
            detail="El escaneo ya fue iniciado o su autorización dejó de estar vigente",
        )


def _start_scan_legacy(client: Client, scan_id: str, source_ids: dict[str, str]) -> None:
    """Compatibilidad para bases que aún no tienen iniciar_escaneo."""
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
    previous: dict[str, Any] | None = None,
    nvd_api_key: str | None = None,
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
    if source_state == "completado" or (source_name in {"crt.sh", "Censys", "theHarvester", "SpiderFoot", "Web"} and bool(outcome.get("contenido"))):
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
                nvd_api_key=nvd_api_key,
                exploit_enrichment=True,
            )
            if previous and summary["ya_procesado"]:
                summary = {**summary, **{
                    key: previous[key] for key in (
                        "resultado_crudo_id", "observaciones_generadas", "activos_nuevos",
                        "activos_existentes", "observaciones_nuevas", "observaciones_duplicadas", "descartadas",
                    )
                }}
            elif previous:
                previous_new_assets = previous.get("activos_nuevos", 0)
                summary["activos_nuevos"] += previous_new_assets
                summary["activos_existentes"] = max(0, summary["activos_existentes"] - previous_new_assets)
                summary["observaciones_nuevas"] += previous.get("observaciones_nuevas", 0)
                summary["observaciones_duplicadas"] = max(
                    0, summary["observaciones_generadas"] - summary["observaciones_nuevas"]
                )
        except Exception as failure:
            logger.exception("No se pudo normalizar o guardar el resultado de %s", source_name)
            detail = ("No se pudo guardar el resultado por un corte de conexión con Supabase"
                      if isinstance(failure, TransportError)
                      else "No se pudo normalizar o guardar el resultado de esta fuente")
            if previous and previous.get("estado") == "completado":
                summary = {key: previous[key] for key in summary}
                error = "; ".join(filter(None, [error, detail]))[:1000]
            else:
                source_state = "fallido"
                error = "; ".join(filter(None, [error, detail]))[:1000]
    status_data = {**summary, "estado": source_state, "error": error, "finalizado_en": _now()}
    _execute(
        client.table("resultados_fuentes")
        .update(status_data)
        .eq("escaneo_id", scan_id)
        .eq("fuente_id", source_id)
    )
    return status_data


def _finish_scan(client: Client, scan_id: str, scan_state: str) -> bool:
    return bool(_execute(
        client.table("escaneos")
        .update({"estado": scan_state, "finalizado_en": _now()})
        .eq("id", scan_id)
        .eq("estado", EJECUTANDO)
    ))


def _cancel_scan(client: Client, scan_id: str) -> bool:
    """La función SQL cambia el estado y cierra las fuentes pendientes en una transacción."""
    try:
        response = client.rpc("cancelar_escaneo", {"p_escaneo_id": scan_id}).execute()
    except APIError as error:
        if error.code == "PGRST202":
            raise HTTPException(status_code=503, detail="Falta aplicar la migración cancelar_escaneo") from error
        raise HTTPException(status_code=502, detail="No se pudo detener el análisis") from error
    except Exception as error:
        raise HTTPException(status_code=502, detail="No se pudo detener el análisis") from error
    return response is not None and response.data is True


async def cancel_scan(client: Client, scan_id: str) -> bool:
    control = _active_scans.get(scan_id)
    if control is None:
        return await run_in_threadpool(_cancel_scan, client, scan_id)
    async with control.persistence_lock:
        cancelled = await run_in_threadpool(_cancel_scan, client, scan_id)
        if cancelled:
            control.cancel_requested.set()
        return cancelled


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
    targets: list[str] | None = None,
    ip_scope: str | None = None,
    excluded_targets: dict[str, str] | None = None,
) -> str:
    """Corre las fuentes, guarda cada una al terminar, cierra el escaneo y calcula el riesgo."""
    scan_id = scan["id"]
    organization_id = scan["organizacion_id"]
    control = _active_scans.setdefault(scan_id, ScanControl())
    persisted: dict[str, dict[str, Any]] = {}
    outcomes = {}
    coverage = None
    disabled_sources = {}
    if runners is None and not getattr(settings, "crtsh_enabled", True):
        disabled_sources["crt.sh"] = CRTSH_DISABLED_REASON
    if runners is None and not settings.web_enabled:
        disabled_sources["Web"] = "Fuente deshabilitada temporalmente: WEB_ENABLED=false en la configuración efectiva."
    if runners is not None and "Web" not in runners:
        disabled_sources["Web"] = "Fuente deshabilitada temporalmente: no se proporcionó un ejecutor Web."

    async def on_result(name: str, outcome: dict[str, Any]) -> None:
        async with control.persistence_lock:
            if control.cancel_requested.is_set():
                return
            try:
                args = (
                    client, organization_id, scan_id, source_ids[name], name, domain, outcome,
                    persisted.get(name), getattr(settings, "nvd_api_key", None),
                )
                persisted[name] = await run_in_threadpool(_persist_source, *args)
            except Exception:
                logger.exception("No se pudo persistir el resultado de %s", name)
                if persisted.get(name, {}).get("estado") == "completado":
                    persisted[name]["error"] = "No se pudo ampliar el resultado de esta fuente"
                else:
                    persisted[name] = {"estado": "fallido", "error": "No se pudo persistir el resultado de esta fuente"}

    try:
        for name, reason in disabled_sources.items():
            try:
                persisted[name] = await run_in_threadpool(
                    _persist_disabled_source, client, scan_id, source_ids[name], reason,
                )
            except Exception:
                logger.exception("No se pudo registrar que %s está deshabilitada", name)
                persisted[name] = {"estado": DISABLED_SOURCE_STATE, "error": reason}
        run_options = {
            "runners": runners,
            "on_result": on_result,
            "timeout_seconds": settings.scan_timeout_seconds,
        }
        if targets is not None:
            run_options["targets"] = targets
            run_options["max_targets"] = settings.scan_max_targets
            run_options["ip_scope"] = ip_scope
            run_options["excluded_targets"] = excluded_targets or {}
        execution_settings = orchestrator_settings(settings)
        collectors = asyncio.create_task(run_all(domain, execution_settings, **run_options))
        cancelled = asyncio.create_task(control.cancel_requested.wait())
        try:
            done, _ = await asyncio.wait({collectors, cancelled}, return_when=asyncio.FIRST_COMPLETED)
            if cancelled in done:
                collectors.cancel()
                await asyncio.gather(collectors, return_exceptions=True)
                return CANCELADO
            try:
                outcomes = await collectors
            except Exception:
                logger.exception("Falló la ejecución de las fuentes del escaneo %s", scan_id)
        finally:
            cancelled.cancel()

        outcomes.update({
            name: {
                "estado": DISABLED_SOURCE_STATE,
                "error": reason,
                "contenido": None,
                "consultas": [],
                "objetivos_pendientes": [],
                "objetivos_omitidos": {},
            }
            for name, reason in disabled_sources.items()
        })

        async with control.persistence_lock:
            if control.cancel_requested.is_set():
                return CANCELADO
            scan_state = compute_scan_state(persisted)
            try:
                assets = await run_in_threadpool(inventory, client, organization_id)
                coverage = build_coverage(assets, outcomes, ip_scope or domain, targets or [domain])
                if coverage["objetivos_pendientes"] and scan_state == COMPLETADO:
                    scan_state = INCOMPLETO
            except Exception:
                logger.exception("No se pudo construir la cobertura por activo")
            finished = await run_in_threadpool(_finish_scan, client, scan_id, scan_state)
            if finished is False:
                return CANCELADO
        logger.info("Escaneo %s: %s", scan_id, scan_message(scan_state, persisted))
        await run_in_threadpool(
            audit,
            client,
            user_id=scan.get("solicitado_por"),
            organization_id=organization_id,
            action="escaneo_finalizado",
            scan_id=scan_id,
            detail={
                "infraestructura": coverage,
                "estado": scan_state,
                "objetivos": targets or [domain],
                "fuentes_ok": [n for n in SOURCE_NAMES if persisted.get(n, {}).get("estado") == COMPLETADO and not persisted.get(n, {}).get("error")],
                "fuentes_fallidas": {
                    n: persisted.get(n, {}).get("error") or "sin resultado"
                    for n in SOURCE_NAMES
                    if persisted.get(n, {}).get("estado") not in {COMPLETADO, DISABLED_SOURCE_STATE}
                    or (persisted.get(n, {}).get("error") and persisted.get(n, {}).get("estado") == COMPLETADO)
                },
                "fuentes_deshabilitadas": disabled_sources,
                "validacion_web": "automatica_en_alcance_autorizado",
            },
        )

        try:
            await calculate_risk_with_retry(client, scan_id, **({"report": coverage} if coverage is not None else {}))
        except Exception:
            # El escaneo ya quedó cerrado; el riesgo se puede recalcular con
            # POST /api/escaneos/{id}/riesgo/recalcular.
            logger.exception("No se pudo calcular el riesgo del escaneo %s", scan_id)
        return scan_state
    finally:
        _active_scans.pop(scan_id, None)


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
