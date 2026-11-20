"""Fuentes y reglas admitidas en el flujo OSINT pasivo actual."""

ACTIVE_SOURCES = ("crt.sh", "theHarvester", "SpiderFoot")

# CONF-006 requiere validación TLS activa. CONF-007 conserva una señal histórica
# de urlscan, pero no puntúa hasta corroborar el certificado servido actualmente.
RETIRED_RISK_RULES = frozenset({
    "CONF-001", "CONF-002",  # Necesitan una comprobación TLS activa de Web.
    "CONF-006", "CONF-007",
})
