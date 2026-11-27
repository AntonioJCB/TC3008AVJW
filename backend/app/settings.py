from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.spiderfoot_passive import DEFAULT_MODULES as DEFAULT_SPIDERFOOT_MODULES


def _enabled(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}

def _clean_secret(value: str) -> str | None:
    value = value.strip()
    if not value or value.lower().startswith(("replace-", "pega-")):
        return None
    return value

@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_service_role_key: str
    censys_pat: str | None
    theharvester_bin: str
    theharvester_sources: str
    spiderfoot_url: str
    request_timeout_seconds: float
    process_timeout_seconds: float
    spiderfoot_timeout_seconds: float
    spiderfoot_poll_seconds: float
    scan_timeout_seconds: float
    crtsh_retries: int
    censys_max_ips: int
    censys_pause_seconds: float
    censys_organization_id: str | None = None
    censys_authorized_ips: str = ""
    web_enabled: bool = True
    frontend_url: str = "http://localhost:5173"
    crtsh_timeout_seconds: float = 15
    crtsh_total_timeout_seconds: float = 45
    crtsh_enabled: bool = True
    spiderfoot_modules: str = DEFAULT_SPIDERFOOT_MODULES
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-5-5"
    assistant_max_tokens: int = 1000
    scan_max_targets: int = 20
    nvd_api_key: str | None = None

    @classmethod
    def from_environment(cls) -> Settings:
        supabase_url = os.getenv("SUPABASE_URL", "").strip()
        service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        if not supabase_url or not service_key or service_key.lower().startswith("replace-"):
            raise RuntimeError(
                "Configura SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY en backend/.env"
            )
        if service_key.startswith("sb_publishable_"):
            raise RuntimeError(
                "SUPABASE_SERVICE_ROLE_KEY contiene una llave pública. Configura la "
                "llave legacy service_role del mismo proyecto en backend/.env; "
                "la llave pública solo corresponde al frontend."
            )
        if service_key.startswith("sb_secret_"):
            raise RuntimeError(
                "La versión instalada de supabase-py (2.15.3) requiere una llave JWT "
                "legacy service_role. Configúrala en SUPABASE_SERVICE_ROLE_KEY; "
                "las llaves sb_secret_ requieren actualizar y validar el SDK."
            )

        censys_pat = os.getenv("CENSYS_PAT", "").strip()
        if censys_pat.lower().startswith("replace-"):
            censys_pat = ""
        nvd_api_key = os.getenv("NVD_API_KEY", "").strip()
        if nvd_api_key.lower().startswith("replace-"):
            nvd_api_key = ""

        return cls(
            supabase_url=supabase_url,
            supabase_service_role_key=service_key,
            censys_pat=censys_pat or None,
            censys_organization_id=os.getenv("CENSYS_ORGANIZATION_ID", "").strip() or None,
            censys_authorized_ips=os.getenv("CENSYS_AUTHORIZED_IPS", "").strip(),
            web_enabled=_enabled("WEB_ENABLED", True),
            nvd_api_key=nvd_api_key or None,
            theharvester_bin=os.getenv("THEHARVESTER_BIN", "theHarvester").strip(),
            theharvester_sources=os.getenv(
                "THEHARVESTER_SOURCES", "certspotter,hackertarget,rapiddns,urlscan"
            ).strip(),
            spiderfoot_url=os.getenv(
                "SPIDERFOOT_URL", "http://127.0.0.1:5001"
            ).rstrip("/"),
            spiderfoot_modules=os.getenv(
                "SPIDERFOOT_MODULES", DEFAULT_SPIDERFOOT_MODULES
            ).strip(),
            request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
            process_timeout_seconds=float(os.getenv("PROCESS_TIMEOUT_SECONDS", "900")),
            spiderfoot_timeout_seconds=float(
                os.getenv("SPIDERFOOT_TIMEOUT_SECONDS", "1800")
            ),
            spiderfoot_poll_seconds=float(os.getenv("SPIDERFOOT_POLL_SECONDS", "3")),
            # Tiempo máximo por fuente; debe ser mayor que SPIDERFOOT_TIMEOUT_SECONDS.
            scan_timeout_seconds=float(os.getenv("SCAN_TIMEOUT_SECONDS", "2100")),
            crtsh_retries=max(1, min(2, int(os.getenv("CRTSH_RETRIES", "2")))),
            frontend_url=os.getenv("FRONTEND_URL", "http://localhost:5173").strip().rstrip("/"),
            crtsh_timeout_seconds=max(
                1, min(15, float(os.getenv("CRTSH_TIMEOUT_SECONDS", "15")))
            ),
            crtsh_total_timeout_seconds=max(
                10, min(90, float(os.getenv("CRTSH_TOTAL_TIMEOUT_SECONDS", "45")))
            ),
            crtsh_enabled=_enabled("CRTSH_ENABLED", True),
            scan_max_targets=max(1, min(100, int(os.getenv("SCAN_MAX_TARGETS", "20")))),
            censys_max_ips=int(os.getenv("CENSYS_MAX_IPS", "10")),
            censys_pause_seconds=float(os.getenv("CENSYS_PAUSE_SECONDS", "1.1")),
            anthropic_api_key=_clean_secret(os.getenv("ANTHROPIC_API_KEY", "")),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-haiku-5-5").strip(),
            assistant_max_tokens=int(os.getenv("ASSISTANT_MAX_TOKENS", "1000")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_environment()
