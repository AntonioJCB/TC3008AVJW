from __future__ import annotations

import ipaddress
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Annotated, Any, AsyncIterator
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from supabase import Client, create_client

from app.orchestrators import Runner, run_all  # noqa: F401  (run_all se re-exporta para las pruebas)
from app.risk.persistencia import calcular_y_guardar, leer_hallazgos, leer_riesgo
from app.scan_service import (  # noqa: F401  (se re-exportan los helpers con su nombre histórico)
    ESTADOS_FINALES,
    SOURCE_NAMES,
    audit,
    _execute,
    _finish_scan,
    _persist_source,
    _source_ids,
    _start_scan,
    compute_scan_state,
    reap_stuck_scans,
    run_scan_job,
    scan_message,
)
from app.settings import Settings, get_settings  # noqa: F401

logger = logging.getLogger(__name__)

INVALID_DOMAIN_DETAIL = "El dominio de la organización no es válido"
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------
# Modelos de respuesta
# ---------------------------------------------------------------------


class SourceStatus(BaseModel):
    fuente: str
    estado: str
    error: str | None = None
    resultado_crudo_id: str | None = None
    iniciado_en: str | None = None
    finalizado_en: str | None = None
    ya_procesado: bool = False
    observaciones_generadas: int = 0
    activos_nuevos: int = 0
    activos_existentes: int = 0
    observaciones_nuevas: int = 0
    observaciones_duplicadas: int = 0
    descartadas: dict[str, int] = Field(default_factory=dict)


class RiskSummary(BaseModel):
    puntaje_global: int
    infraestructura: int
    identidad_digital: int
    configuracion: int
    fuga_de_datos: int
    #: True si alguna fuente falló: el puntaje no vio todo y puede estar subestimado.
    es_parcial: bool = False
    fuentes_faltantes: list[str] = Field(default_factory=list)
    #: Qué reglas se evaluaron y cuáles no (y por qué).
    cobertura: dict[str, Any] = Field(default_factory=dict)
    version_motor: str | None = None
    calculado_en: str | None = None


class ScanStatus(BaseModel):
    escaneo_id: str
    estado: str
    fuentes: list[SourceStatus]
    #: Frase lista para mostrar: qué fuentes fallaron y cuáles no.
    mensaje: str = ""
    dominio: str | None = None
    fuentes_ok: list[str] = Field(default_factory=list)
    fuentes_fallidas: list[str] = Field(default_factory=list)
    iniciado_en: str | None = None
    finalizado_en: str | None = None
    riesgo: RiskSummary | None = None


class CreateScan(BaseModel):
    autorizacion_id: UUID


class ScanCreated(BaseModel):
    escaneo_id: str
    estado: str
    dominio: str


class ScanSummary(BaseModel):
    escaneo_id: str
    estado: str
    dominio: str
    iniciado_en: str | None = None
    finalizado_en: str | None = None
    puntaje_global: int | None = None
    es_parcial: bool | None = None


class Finding(BaseModel):
    id: str
    regla_codigo: str | None = None
    regla_nombre: str | None = None
    descripcion: str | None = None
    categoria: str
    severidad: str
    confianza: float
    estado: str
    activo_tipo: str | None = None
    activo_valor: str | None = None
    fuentes: list[str] = Field(default_factory=list)
    evidencia: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------
# Cliente, autenticación y validación de alcance
# ---------------------------------------------------------------------


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


async def _current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Any:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Se requiere una sesión válida")
    # Rechaza entradas como '1' antes de construir el cliente. Supabase verifica
    # la autenticidad del JWT en get_user; este chequeo solo valida su estructura.
    if len(credentials.credentials.split(".")) != 3 or not all(credentials.credentials.split(".")):
        raise HTTPException(status_code=401, detail="Se requiere el access_token de una sesión de Supabase")
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


def _get_profile(client: Client, user_id: str, require_analyst: bool) -> dict[str, Any]:
    profile = _execute(
        client.table("usuarios")
        .select("organizacion_id, rol, esta_activo")
        .eq("id", user_id)
        .maybe_single()
    )
    if not profile or not profile.get("esta_activo") or not profile.get("organizacion_id"):
        raise HTTPException(status_code=403, detail="El usuario no tiene acceso a una organización activa")
    if require_analyst and profile.get("rol") not in {"admin", "analista"}:
        raise HTTPException(status_code=403, detail="El usuario no tiene permiso para iniciar escaneos")
    return profile


def _get_scan(
    client: Client,
    user_id: str,
    organization_id: str,
    scan_id: str,
    only_requester: bool = True,
) -> dict[str, Any]:
    """Un escaneo se ve si es de tu organización; solo quien lo pidió puede ejecutarlo."""
    scan = _execute(
        client.table("escaneos")
        .select("id, organizacion_id, solicitado_por, autorizacion_id, estado, iniciado_en, finalizado_en")
        .eq("id", scan_id)
        .maybe_single()
    )
    if (
        not scan
        or scan.get("organizacion_id") != organization_id
        or (only_requester and scan.get("solicitado_por") != user_id)
    ):
        raise HTTPException(status_code=404, detail="No se encontró el escaneo solicitado")
    return scan


def _authorized_domain(client: Client, scan: dict[str, Any]) -> str:
    """Valida la autorización (vigente, de la organización, con el dominio en su alcance).

    El dominio que se escanea SIEMPRE es organizaciones.dominio_principal: nunca
    viene del cliente.
    """
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
    scan = _get_scan(client, user_id, profile["organizacion_id"], scan_id, only_requester=require_pending)
    if not require_pending:
        return scan, ""
    if scan.get("estado") != "pendiente":
        raise HTTPException(status_code=409, detail="El escaneo ya fue iniciado o finalizado")
    return scan, _authorized_domain(client, scan)


# ---------------------------------------------------------------------
# Construcción de respuestas
# ---------------------------------------------------------------------

_PENDIENTE = {"estado": "pendiente", "error": None, "resultado_crudo_id": None, "finalizado_en": None}


def _source_results(client: Client, scan_id: str) -> dict[str, dict[str, Any]]:
    rows = _execute(
        client.table("resultados_fuentes")
        .select(
            "estado, error, resultado_crudo_id, iniciado_en, finalizado_en, ya_procesado, "
            "observaciones_generadas, activos_nuevos, activos_existentes, "
            "observaciones_nuevas, observaciones_duplicadas, descartadas, fuentes_osint(nombre)"
        )
        .eq("escaneo_id", scan_id)
    ) or []
    results: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not row.get("fuentes_osint"):
            continue
        results[row["fuentes_osint"]["nombre"]] = {
            key: row.get(key)
            for key in (
                "estado", "error", "resultado_crudo_id", "iniciado_en", "finalizado_en", "ya_procesado",
                "observaciones_generadas", "activos_nuevos", "activos_existentes",
                "observaciones_nuevas", "observaciones_duplicadas", "descartadas",
            )
            if row.get(key) is not None
        }
    for name in SOURCE_NAMES:
        results.setdefault(name, dict(_PENDIENTE))
    return results


def _status_response(
    scan_id: str,
    scan_state: str,
    results: dict[str, dict[str, Any]],
    **extra: Any,
) -> ScanStatus:
    return ScanStatus(
        escaneo_id=scan_id,
        estado=scan_state,
        fuentes=[SourceStatus(fuente=name, **results[name]) for name in SOURCE_NAMES],
        mensaje=scan_message(scan_state, results),
        fuentes_ok=[n for n in SOURCE_NAMES if results[n].get("estado") == "completado"],
        fuentes_fallidas=[n for n in SOURCE_NAMES if results[n].get("estado") == "fallido"],
        **extra,
    )


def _organization_domain(client: Client, organization_id: str) -> str | None:
    row = _execute(
        client.table("organizaciones").select("dominio_principal").eq("id", organization_id).maybe_single()
    )
    return row["dominio_principal"] if row else None


def _risk_or_none(client: Client, scan_id: str) -> RiskSummary | None:
    riesgo = leer_riesgo(client, scan_id)
    return RiskSummary(**riesgo) if riesgo else None


# ---------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Al arrancar, cierra escaneos que quedaron 'ejecutando' por un reinicio anterior."""
    try:
        settings = get_settings()
        cerrados = await run_in_threadpool(
            reap_stuck_scans, _supabase_client(), settings.scan_timeout_seconds + 600
        )
        if cerrados:
            logger.warning("Se cerraron %s escaneos interrumpidos", cerrados)
    except Exception:
        logger.warning("No se pudo revisar si había escaneos interrumpidos", exc_info=True)
    yield


app = FastAPI(title="BaxterSec OSINT API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_runners() -> dict[str, Runner] | None:
    """None = las cuatro fuentes reales. Las pruebas lo sobrescriben con fuentes falsas."""
    return None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"estado": "disponible"}


@app.post("/api/escaneos", status_code=201, response_model=ScanCreated)
async def create_scan(
    body: CreateScan,
    user: Annotated[Any, Depends(_current_user)],
) -> ScanCreated:
    """Crea un escaneo 'pendiente' para tu organización, con una autorización vigente."""
    client = _supabase_client()
    profile = await run_in_threadpool(_get_profile, client, str(user.id), True)
    organization_id = profile["organizacion_id"]
    authorization_id = str(body.autorizacion_id)
    domain = await run_in_threadpool(
        _authorized_domain, client, {"organizacion_id": organization_id, "autorizacion_id": authorization_id}
    )
    created = await run_in_threadpool(
        _execute,
        client.table("escaneos").insert(
            {
                "organizacion_id": organization_id,
                "solicitado_por": str(user.id),
                "autorizacion_id": authorization_id,
                "estado": "pendiente",
            }
        ),
    )
    await run_in_threadpool(
        audit,
        client,
        user_id=str(user.id),
        organization_id=organization_id,
        action="escaneo_creado",
        scan_id=created[0]["id"],
        detail={"dominio": domain, "autorizacion_id": authorization_id},
    )
    return ScanCreated(escaneo_id=created[0]["id"], estado="pendiente", dominio=domain)


@app.get("/api/escaneos", response_model=list[ScanSummary])
async def list_scans(
    user: Annotated[Any, Depends(_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ScanSummary]:
    """Historial de escaneos de tu organización, del más reciente al más antiguo."""
    client = _supabase_client()
    profile = await run_in_threadpool(_get_profile, client, str(user.id), False)
    organization_id = profile["organizacion_id"]
    domain = await run_in_threadpool(_organization_domain, client, organization_id) or ""
    rows = await run_in_threadpool(
        _execute,
        client.table("escaneos")
        .select("id, estado, iniciado_en, finalizado_en, puntajes_riesgo(puntaje_global, es_parcial)")
        .eq("organizacion_id", organization_id)
        .order("iniciado_en", desc=True, nullsfirst=True)
        .limit(limit),
    ) or []
    summaries = []
    for row in rows:
        score = row.get("puntajes_riesgo")
        if isinstance(score, list):  # según cómo infiera PostgREST la relación
            score = score[0] if score else None
        summaries.append(
            ScanSummary(
                escaneo_id=row["id"],
                estado=row["estado"],
                dominio=domain,
                iniciado_en=row.get("iniciado_en"),
                finalizado_en=row.get("finalizado_en"),
                puntaje_global=score["puntaje_global"] if score else None,
                es_parcial=score["es_parcial"] if score else None,
            )
        )
    return summaries


@app.post("/api/escaneos/{scan_id}/ejecutar", status_code=202, response_model=ScanStatus)
async def execute_scan(
    scan_id: UUID,
    background: BackgroundTasks,
    user: Annotated[Any, Depends(_current_user)],
    runners: Annotated[dict[str, Runner] | None, Depends(get_runners)],
) -> ScanStatus:
    """Inicia el escaneo y responde de inmediato (202).

    Las cuatro fuentes corren en segundo plano. Consulta `GET /api/escaneos/{id}`
    para ver el avance y, al final, qué fuentes fallaron y cuáles no.
    """
    settings = get_settings()
    client = _supabase_client()
    scan_id_text = str(scan_id)
    scan, domain = await run_in_threadpool(_verify_scope, client, str(user.id), scan_id_text)
    source_ids = await run_in_threadpool(_source_ids, client)
    await run_in_threadpool(_start_scan, client, scan_id_text, source_ids)

    background.add_task(run_scan_job, client, settings, scan, source_ids, domain, runners)
    running = {name: {"estado": "ejecutando"} for name in SOURCE_NAMES}
    return _status_response(scan_id_text, "ejecutando", running, dominio=domain)


@app.get("/api/escaneos/{scan_id}", response_model=ScanStatus)
async def get_scan(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> ScanStatus:
    """Estado del escaneo, de cada fuente (cuál falló y cuál no) y el riesgo si ya se calculó."""
    client = _supabase_client()
    scan, _ = await run_in_threadpool(_verify_scope, client, str(user.id), str(scan_id), False)
    results = await run_in_threadpool(_source_results, client, str(scan_id))
    domain = await run_in_threadpool(_organization_domain, client, scan["organizacion_id"])
    risk = await run_in_threadpool(_risk_or_none, client, str(scan_id))
    return _status_response(
        str(scan_id),
        scan["estado"],
        results,
        dominio=domain,
        iniciado_en=scan.get("iniciado_en"),
        finalizado_en=scan.get("finalizado_en"),
        riesgo=risk,
    )


@app.get("/api/escaneos/{scan_id}/fuentes", response_model=ScanStatus)
async def get_scan_sources(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> ScanStatus:
    client = _supabase_client()
    scan, _ = await run_in_threadpool(_verify_scope, client, str(user.id), str(scan_id), False)
    results = await run_in_threadpool(_source_results, client, str(scan_id))
    return _status_response(str(scan_id), scan["estado"], results)


@app.get("/api/escaneos/{scan_id}/hallazgos", response_model=list[Finding])
async def get_findings(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> list[Finding]:
    """Hallazgos del escaneo, de mayor a menor severidad."""
    client = _supabase_client()
    await run_in_threadpool(_verify_scope, client, str(user.id), str(scan_id), False)
    rows = await run_in_threadpool(leer_hallazgos, client, str(scan_id))
    findings = []
    for row in rows:
        rule = row.get("reglas_riesgo") or {}
        asset = row.get("activos") or {}
        evidence = row.get("evidencia") or {}
        findings.append(
            Finding(
                id=row["id"],
                regla_codigo=rule.get("codigo"),
                regla_nombre=rule.get("nombre"),
                descripcion=rule.get("descripcion"),
                categoria=row["categoria"],
                severidad=row["severidad"],
                confianza=float(row["confianza"]),
                estado=row["estado"],
                activo_tipo=asset.get("tipo"),
                activo_valor=asset.get("valor"),
                fuentes=evidence.get("fuentes") or [n for n in [(row.get("fuentes_osint") or {}).get("nombre")] if n],
                evidencia=evidence,
            )
        )
    return findings


@app.get("/api/escaneos/{scan_id}/riesgo", response_model=RiskSummary)
async def get_risk(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> RiskSummary:
    client = _supabase_client()
    await run_in_threadpool(_verify_scope, client, str(user.id), str(scan_id), False)
    risk = await run_in_threadpool(_risk_or_none, client, str(scan_id))
    if risk is None:
        raise HTTPException(status_code=404, detail="El riesgo de este escaneo aún no se ha calculado")
    return risk


@app.post("/api/escaneos/{scan_id}/riesgo/recalcular", response_model=RiskSummary)
async def recalculate_risk(
    scan_id: UUID,
    user: Annotated[Any, Depends(_current_user)],
) -> RiskSummary:
    """Recalcula hallazgos y puntajes con las observaciones ya guardadas (sin volver a escanear).

    Útil después de ajustar pesos en `reglas_riesgo` o de corregir un fallo del motor.
    """
    client = _supabase_client()
    profile = await run_in_threadpool(_get_profile, client, str(user.id), True)
    scan = await run_in_threadpool(
        _get_scan, client, str(user.id), profile["organizacion_id"], str(scan_id), False
    )
    if scan["estado"] not in ESTADOS_FINALES:
        raise HTTPException(status_code=409, detail="El escaneo aún no ha terminado")
    try:
        await run_in_threadpool(calcular_y_guardar, client, str(scan_id))
    except Exception as error:
        logger.exception("No se pudo recalcular el riesgo del escaneo %s", scan_id)
        raise HTTPException(status_code=502, detail="No se pudo calcular el riesgo del escaneo") from error
    risk = await run_in_threadpool(_risk_or_none, client, str(scan_id))
    if risk is None:  # no debería ocurrir: acabamos de guardarlo
        raise HTTPException(status_code=502, detail="No se pudo leer el riesgo calculado")
    return risk
