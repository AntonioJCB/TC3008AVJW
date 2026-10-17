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

    @classmethod
    def from_environment(cls) -> Settings:
        supabase_url = os.getenv("SUPABASE_URL", "").strip()
        service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        if not supabase_url or not service_key or service_key.lower().startswith("replace-"):
            raise RuntimeError(
                "Configura SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY en backend/.env"
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
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_environment()