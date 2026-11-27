"""Fuentes y reglas admitidas en el flujo de análisis."""

ACTIVE_SOURCES = ("crt.sh", "Censys", "theHarvester", "SpiderFoot", "Web")


def enabled_runner_sources(*, crtsh_enabled: bool, web_enabled: bool) -> tuple[str, ...]:
    """Colectores que el orquestador incorpora a un análisis nuevo."""
    return tuple(name for name in ACTIVE_SOURCES if (
        (name != "crt.sh" or crtsh_enabled)
        and (name != "Web" or web_enabled)
    ))

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

RETIRED_RISK_RULES = frozenset({"CONF-001", "CONF-002"})
# La evidencia histórica de urlscan sigue siendo potencial en sus evaluadores.
POTENTIAL_ONLY_RISK_RULES = frozenset({"CONF-004"})
