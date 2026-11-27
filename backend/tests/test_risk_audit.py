from datetime import datetime, timezone
import pytest
from app.osint_normalization import adaptar
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo

RULES = [Regla("ssh", "INFRA-001", "SSH", "infraestructura", "alta", 15),
         Regla("db", "INFRA-002", "DB", "infraestructura", "critica", 30),
         Regla("cve", "INFRA-003", "CVE", "infraestructura", "media", 8),
         Regla("mail", "IDEN-003", "Correo", "identidad_digital", "baja", 0)]

@pytest.mark.parametrize("event,expected", [
 ({"event_type":"INTERNET_NAME", "data":"api.example.com"},0),
 ({"event_type":"TCP_PORT_OPEN", "data":"203.0.113.10:22"},13),
 ({"event_type":"TCP_PORT_OPEN", "data":"203.0.113.10:5432"},26),
 ({"event_type":"VULNERABILITY_CVE_HIGH", "data":"CVE-2024-12345", "source_data":"api.example.com"},0),
 ({"event_type":"EMAILADDR", "data":"public@example.com"},0),
])
def test_normalizador_y_motor_con_evidencia_controlada(event, expected):
    normalized = adaptar("SpiderFoot", [event], "example.com")
    observations = [Obs(str(i), row["valor"], row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf") for i,row in enumerate(normalized["observaciones"])]
    result = evaluar_riesgo(observations, RULES, {"SpiderFoot":"completado"}, datetime(2026,11,18,tzinfo=timezone.utc))
    assert result.puntaje.puntaje_global == expected

@pytest.mark.parametrize("flag", [True, 1, "1", "true"])
def test_spiderfoot_falso_positivo_explicito_no_puntua(flag):
    result = adaptar("SpiderFoot", [{"event_type":"TCP_PORT_OPEN", "data":"203.0.113.10:22", "false_positive":flag}], "example.com")
    assert result["observaciones"] == []
    assert result["descartadas"][0]["motivo"] == "falso_positivo_fuente"

@pytest.mark.parametrize("flag", [False, 0, "0", "false", None])
def test_spiderfoot_sin_descarte_explicito_conserva_evidencia(flag):
    result = adaptar("SpiderFoot", [{"event_type":"TCP_PORT_OPEN", "data":"203.0.113.10:22", "false_positive":flag}], "example.com")
    assert any(row["atributo"] == "servicio_expuesto" for row in result["observaciones"])
