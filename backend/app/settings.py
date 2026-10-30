from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env")


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_service_role_key: str
    shodan_api_key: str | None
    theharvester_bin: str
    theharvester_sources: str
    spiderfoot_url: str
    request_timeout_seconds: float
    process_timeout_seconds: float
    spiderfoot_timeout_seconds: float
    spiderfoot_poll_seconds: float
    scan_timeout_seconds: float
    crtsh_retries: int
    shodan_max_ips: int
    shodan_pause_seconds: float

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

        shodan_api_key = os.getenv("SHODAN_API_KEY", "").strip()
        if shodan_api_key.lower().startswith("replace-"):
            shodan_api_key = ""

        return cls(
            supabase_url=supabase_url,
            supabase_service_role_key=service_key,
            shodan_api_key=shodan_api_key or None,
            theharvester_bin=os.getenv("THEHARVESTER_BIN", "theHarvester").strip(),
            theharvester_sources=os.getenv(
                "THEHARVESTER_SOURCES", "crtsh,certspotter"
            ).strip(),
            spiderfoot_url=os.getenv(
                "SPIDERFOOT_URL", "http://127.0.0.1:5001"
            ).rstrip("/"),
            request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
            process_timeout_seconds=float(os.getenv("PROCESS_TIMEOUT_SECONDS", "900")),
            spiderfoot_timeout_seconds=float(
                os.getenv("SPIDERFOOT_TIMEOUT_SECONDS", "1800")
            ),
            spiderfoot_poll_seconds=float(os.getenv("SPIDERFOOT_POLL_SECONDS", "3")),
            # Tiempo máximo por fuente; debe ser mayor que SPIDERFOOT_TIMEOUT_SECONDS.
            scan_timeout_seconds=float(os.getenv("SCAN_TIMEOUT_SECONDS", "2100")),
            crtsh_retries=int(os.getenv("CRTSH_RETRIES", "3")),
            shodan_max_ips=int(os.getenv("SHODAN_MAX_IPS", "10")),
            shodan_pause_seconds=float(os.getenv("SHODAN_PAUSE_SECONDS", "1.1")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_environment()
