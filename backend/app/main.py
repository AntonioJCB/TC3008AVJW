from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from supabase import Client, create_client

from app.ingestion import ingestar_resultado
from app.orchestrators import OrchestratorSettings, run_all
from app.settings import Settings, get_settings


SOURCE_NAMES = ("crt.sh", "Shodan", "theHarvester", "SpiderFoot")
INVALID_DOMAIN_DETAIL = "El dominio de la organización no es válido"
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
bearer = HTTPBearer(auto_error=False)


class SourceStatus(BaseModel):
    fuente: str
    estado: str
    error: str | None = None
    resultado_crudo_id: str | None = None
    finalizado_en: str | None = None
    ya_procesado: bool = False
    observaciones_generadas: int = 0
    activos_nuevos: int = 0
    activos_existentes: int = 0
    observaciones_nuevas: int = 0
    observaciones_duplicadas: int = 0
    descartadas: dict[str, int] = Field(default_factory=dict)


class ScanStatus(BaseModel):
    escaneo_id: str
    estado: str
    fuentes: list[SourceStatus]


@lru_cache(maxsize=1)
def _supabase_client() -> Client:
    settings = get_settings()
    return create_client(settings.supabase_url, settings.supabase_service_role_key)


def _canonical_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or any(character in candidate for character in "/:@?#"):
        raise HTTPException(status_code=400, detail=INVALID_DOMAIN_DETAIL)
    try:
        domain = candidate.encode("idna").decode("ascii")
        ipaddress.ip_address(domain)
    except UnicodeError as error:
        raise HTTPException(status_code=400, detail=INVALID_DOMAIN_DETAIL) from error
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=400, detail="El alcance debe ser un nombre de dominio")

    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(not DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise HTTPException(status_code=400, detail=INVALID_DOMAIN_DETAIL)
    return domain


def _scope_allows_domain(scope: str, domain: str) -> bool:
    for entry in re.split(r"[\s,;]+", scope):
        token = entry.strip("()[]{}<>\"'.,")
        if not token:
            continue
        wildcard = token.startswith("*.")
        try:
            candidate = _canonical_domain(token[2:] if wildcard else token)
        except HTTPException:
            continue
        if candidate == domain and not wildcard:
            return True
    return False


def _execute(query: Any) -> Any:
    try:
        return query.execute().data
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo consultar o actualizar el estado del escaneo en Supabase",
        ) from error


async def _current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Any:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Se requiere una sesión válida")
    try:
        client = _supabase_client()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=503, detail="Supabase no está disponible") from error
    try:
        response = await run_in_threadpool(client.auth.get_user, credentials.credentials)
    except Exception as error:
        raise HTTPException(status_code=401, detail="La sesión de Supabase no es válida") from error
    if response.user is None:
        raise HTTPException(status_code=401, detail="La sesión de Supabase no es válida")
    return response.user


def _orchestrator_settings(settings: Settings) -> OrchestratorSettings:
    return OrchestratorSettings(
        shodan_api_key=settings.shodan_api_key,
        theharvester_bin=settings.theharvester_bin,
        theharvester_sources=settings.theharvester_sources,
        spiderfoot_url=settings.spiderfoot_url,
        request_timeout_seconds=settings.request_timeout_seconds,
        process_timeout_seconds=settings.process_timeout_seconds,
        spiderfoot_timeout_seconds=settings.spiderfoot_timeout_seconds,
        spiderfoot_poll_seconds=settings.spiderfoot_poll_seconds,
    )


def _get_profile(client: Client, user_id: str, require_analyst: bool) -> dict[str, Any]:
    profile = _execute(
        client.table("usuarios")
        .select("organizacion_id, rol, esta_activo")
        .eq("id", user_id)
        .maybe_single()
    )
    if not profile or not profile.get("esta_activo"):
        raise HTTPException(status_code=403, detail="El usuario no puede iniciar escaneos")
    if require_analyst and profile.get("rol") not in {"admin", "analista"}:
        raise HTTPException(status_code=403, detail="El usuario no puede iniciar escaneos")
    return profile


def _get_scan(
    client: Client, user_id: str, organization_id: str, scan_id: str
) -> dict[str, Any]:
    scan = _execute(
        client.table("escaneos")
        .select("id, organizacion_id, solicitado_por, autorizacion_id, estado")
        .eq("id", scan_id)
        .maybe_single()
    )
    if (
        not scan
        or scan.get("solicitado_por") != user_id
        or scan.get("organizacion_id") != organization_id
    ):
        raise HTTPException(status_code=404, detail="No se encontró el escaneo solicitado")
    return scan


def _authorized_domain(client: Client, scan: dict[str, Any]) -> str:
    authorization = _execute(
        client.table("autorizaciones_dominio")
        .select("organizacion_id, alcance, expira_en, revocada_en")
        .eq("id", scan["autorizacion_id"])
        .maybe_single()
    )
    if (
        not authorization
        or authorization.get("organizacion_id") != scan.get("organizacion_id")
        or authorization.get("revocada_en") is not None
    ):
        raise HTTPException(status_code=403, detail="La autorización del escaneo no está vigente")
    expiry = authorization.get("expira_en")
    if expiry:
        expiry_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        if expiry_date <= datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="La autorización del escaneo ha expirado")

    organization = _execute(
        client.table("organizaciones")
        .select("dominio_principal")
        .eq("id", scan["organizacion_id"])
        .maybe_single()
    )
    if not organization:
        raise HTTPException(status_code=404, detail="No se encontró la organización del escaneo")
    domain = _canonical_domain(organization["dominio_principal"])
    if not _scope_allows_domain(str(authorization.get("alcance") or ""), domain):
        raise HTTPException(
            status_code=403,
            detail="El dominio principal no está incluido explícitamente en el alcance autorizado",
        )
    return domain


def _verify_scope(
    client: Client,
    user_id: str,
    scan_id: str,
    require_pending: bool = True,
) -> tuple[dict[str, Any], str]:
    profile = _get_profile(client, user_id, require_pending)
    scan = _get_scan(client, user_id, profile["organizacion_id"], scan_id)
    if not require_pending:
        return scan, ""
    if scan.get("estado") != "pendiente":
        raise HTTPException(status_code=409, detail="El escaneo ya fue iniciado o finalizado")
    return scan, _authorized_domain(client, scan)


def _start_scan(client: Client, scan_id: str, source_ids: dict[str, str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    claimed = _execute(
        client.table("escaneos")
        .update({"estado": "ejecutando", "iniciado_en": now})
        .eq("id", scan_id)
        .eq("estado", "pendiente")
        .select("id")
    )
    if not claimed:
        raise HTTPException(status_code=409, detail="El escaneo ya fue iniciado por otra solicitud")
    rows = [
        {
            "escaneo_id": scan_id,
            "fuente_id": source_ids[name],
            "estado": "ejecutando",
            "iniciado_en": now,
        }
        for name in SOURCE_NAMES
    ]
    _execute(
        client.table("resultados_fuentes")
        .upsert(rows, on_conflict="escaneo_id,fuente_id")
    )


def _persist_source(
    client: Client,
    organization_id: str,
    scan_id: str,
    source_id: str,
    source_name: str,
    domain: str,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    summary = {
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
            )
        except Exception:
            source_state = "fallido"
            error = "No se pudo normalizar o guardar el resultado de esta fuente"
    status_data = {
        **summary,
        "estado": source_state,
        "error": error,
        "finalizado_en": now,
    }
    _execute(
        client.table("resultados_fuentes")
        .update(status_data)
        .eq("escaneo_id", scan_id)
        .eq("fuente_id", source_id)
    )
    return status_data


def _finish_scan(client: Client, scan_id: str, scan_state: str) -> None:
    _execute(
        client.table("escaneos")
        .update(
            {
                "estado": scan_state,
                "finalizado_en": datetime.now(timezone.utc).isoformat(),
            }
        )
        .eq("id", scan_id)
    )


def _source_ids(client: Client) -> dict[str, str]:
    rows = _execute(
        client.table("fuentes_osint")
        .select("id, nombre")
        .in_("nombre", list(SOURCE_NAMES))
    ) or []
    found = {row["nombre"]: row["id"] for row in rows}
    missing = set(SOURCE_NAMES) - found.keys()
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Faltan fuentes en el catálogo de Supabase: {', '.join(sorted(missing))}",
        )
    return found


def _status_response(scan_id: str, scan_state: str, results: dict[str, dict[str, Any]]) -> ScanStatus:
    return ScanStatus(
        escaneo_id=scan_id,
        estado=scan_state,
        fuentes=[
            SourceStatus(fuente=name, **results[name])
            for name in SOURCE_NAMES
        ],
    )


app = FastAPI(title="BaxterSec OSINT API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"estado": "disponible"}


@app.post("/api/escaneos/{scan_id}/ejecutar")
async def execute_scan(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> ScanStatus:
    settings = get_settings()
    client = _supabase_client()
    scan_id_text = str(scan_id)
    scan, domain = await run_in_threadpool(
        _verify_scope, client, str(user.id), scan_id_text
    )
    source_ids = await run_in_threadpool(_source_ids, client)
    await run_in_threadpool(_start_scan, client, scan_id_text, source_ids)

    outcomes = await run_all(domain, _orchestrator_settings(settings))
    persisted: dict[str, dict[str, Any]] = {}
    for name in SOURCE_NAMES:
        try:
            persisted[name] = await run_in_threadpool(
                _persist_source,
                client,
                scan["organizacion_id"],
                scan_id_text,
                source_ids[name],
                name,
                domain,
                outcomes[name],
            )
        except Exception:
            persisted[name] = {
                "estado": "fallido",
                "error": "No se pudo persistir el resultado de esta fuente",
                "resultado_crudo_id": None,
                "finalizado_en": datetime.now(timezone.utc).isoformat(),
            }

    scan_state = (
        "completado"
        if all(result["estado"] == "completado" for result in persisted.values())
        else "incompleto"
    )
    await run_in_threadpool(_finish_scan, client, scan_id_text, scan_state)
    return _status_response(scan_id_text, scan_state, persisted)


@app.get("/api/escaneos/{scan_id}/fuentes")
async def get_scan_sources(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> ScanStatus:
    client = _supabase_client()
    scan, _ = await run_in_threadpool(
        _verify_scope, client, str(user.id), str(scan_id), False
    )
    rows = await run_in_threadpool(
        _execute,
        client.table("resultados_fuentes")
        .select(
            "estado, error, resultado_crudo_id, finalizado_en, ya_procesado, "
            "observaciones_generadas, activos_nuevos, activos_existentes, "
            "observaciones_nuevas, observaciones_duplicadas, descartadas, fuentes_osint(nombre)"
        )
        .eq("escaneo_id", str(scan_id)),
    ) or []
    results = {
        row["fuentes_osint"]["nombre"]: {
            "estado": row["estado"],
            "error": row.get("error"),
            "resultado_crudo_id": row.get("resultado_crudo_id"),
            "finalizado_en": row.get("finalizado_en"),
            "ya_procesado": row.get("ya_procesado", False),
            "observaciones_generadas": row.get("observaciones_generadas", 0),
            "activos_nuevos": row.get("activos_nuevos", 0),
            "activos_existentes": row.get("activos_existentes", 0),
            "observaciones_nuevas": row.get("observaciones_nuevas", 0),
            "observaciones_duplicadas": row.get("observaciones_duplicadas", 0),
            "descartadas": row.get("descartadas", {}),
        }
        for row in rows
        if row.get("fuentes_osint")
    }
    for name in SOURCE_NAMES:
        results.setdefault(
            name,
            {"estado": "pendiente", "error": None, "resultado_crudo_id": None, "finalizado_en": None},
        )
    return _status_response(str(scan_id), scan["estado"], results)