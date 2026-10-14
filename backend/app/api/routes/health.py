from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.core.config import Settings, get_settings
from app.schemas.health import HealthResponse
from app.services.health import database_is_ready

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def process_health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/db", response_model=HealthResponse)
def database_health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    if settings.database_url is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    if not database_is_ready(str(settings.database_url)):
        raise HTTPException(status_code=503, detail="Database unavailable")

    return HealthResponse(status="ok")
