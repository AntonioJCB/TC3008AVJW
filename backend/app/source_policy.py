"""Fuentes y reglas admitidas en el flujo OSINT pasivo actual."""

ACTIVE_SOURCES = ("crt.sh", "theHarvester", "SpiderFoot")

DISABLED_SOURCE_STATE = "deshabilitado"
DISABLED_SOURCE_PREFIX = "Fuente deshabilitada temporalmente:"
CRTSH_DISABLED_REASON = (
    f"{DISABLED_SOURCE_PREFIX} crt.sh continúa devolviendo HTTP 502; "
    "no se evaluó Certificate Transparency y esa cobertura queda pendiente."
)


def is_disabled_source_result(state: str | None, error: str | None) -> bool:
    return state == DISABLED_SOURCE_STATE or (
        state == "pendiente" and str(error or "").startswith(DISABLED_SOURCE_PREFIX)
    )

# Las reglas retiradas requieren comprobaciones TLS activas.
RETIRED_RISK_RULES = frozenset({"CONF-001", "CONF-002", "CONF-006"})
# La evidencia histórica de urlscan solo califica como potencial.
POTENTIAL_ONLY_RISK_RULES = frozenset({"CONF-004", "CONF-007", "CONF-008"})
