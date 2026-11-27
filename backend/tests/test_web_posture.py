import asyncio
import socket
import ssl
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.osint_normalization import adaptar
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo
from app.web_posture import inspect_host


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_certificado_verificado_por_expirar_y_http_redirigido_no_suma_http():
    expiry = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    with patch("app.web_posture._public_addresses", new=AsyncMock(return_value=["8.8.8.8"])), patch(
        "app.web_posture._head", new=AsyncMock(side_effect=[
            (200, {}, {"notAfter": expiry}),
            (308, {"location": "https://api.example.com/"}, {}),
        ])
    ) as head:
        events, errors = await inspect_host("api.example.com")
    assert errors == []
    assert {event["check"] for event in events} == {"tls_verificado", "tls_por_expirar"}
    assert head.await_count == 2
    assert all(call.args[0] == "api.example.com" for call in head.await_args_list)
    assert [(call.args[1], call.args[2]) for call in head.await_args_list] == [("8.8.8.8", 443), ("8.8.8.8", 80)]


@pytest.mark.anyio
async def test_certificado_invalido_y_http_claro_producen_evidencia():
    invalid = ssl.SSLCertVerificationError("certificate verify failed")
    with patch("app.web_posture._public_addresses", new=AsyncMock(return_value=["8.8.8.8"])), patch(
        "app.web_posture._head", new=AsyncMock(side_effect=[invalid, (200, {}, {})])
    ):
        events, errors = await inspect_host("api.example.com")
    assert errors == []
    assert {event["check"] for event in events} == {"tls_invalido", "http_sin_redireccion"}


@pytest.mark.anyio
async def test_ip_no_publica_no_recibe_conexion():
    records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=records)), patch(
        "app.web_posture._head", new=AsyncMock()
    ) as head:
        with pytest.raises(ValueError):
            await inspect_host("api.example.com")
    head.assert_not_awaited()


def test_web_confirma_solo_evidencia_actual_y_no_puntua_inconclusos():
    raw = [
        {"host": "api.example.com", "check": "tls_invalido", "verify_code": 10, "validation_mode": "active-authorized-v1"},
        {"host": "shop.example.com", "check": "http_sin_redireccion", "status": 200, "validation_mode": "active-authorized-v1"},
        {"host": "dev.example.com", "check": "tls_verificado", "validation_mode": "active-authorized-v1"},
    ]
    items = adaptar("Web", raw, "example.com")["observaciones"]
    observations = [
        Obs(str(i), f"asset-{item['valor']}", item["tipo"], item["valor"],
            item["atributo"], item["datos"], "Web", "source-web")
        for i, item in enumerate(items)
    ]
    rules = [
        Regla("invalid", "CONF-006", "TLS inválido", "configuracion", "media", 12),
        Regla("http", "CONF-008", "HTTP claro", "configuracion", "media", 6),
    ]
    risk = evaluar_riesgo(observations, rules, {"Web": "completado"})
    assert {finding.regla_codigo for finding in risk.hallazgos} == {"CONF-006", "CONF-008"}
    assert all(finding.nivel_evidencia == "confirmada" for finding in risk.hallazgos)
    assert risk.puntaje.puntaje_global > 0
    assert adaptar("Web", [{"host": "other.net", "check": "tls_invalido"}], "example.com")["observaciones"] == []


@pytest.mark.anyio
async def test_web_inconcluso_no_genera_hallazgo():
    with patch("app.web_posture._public_addresses", new=AsyncMock(return_value=["8.8.8.8"])), patch(
        "app.web_posture._head", new=AsyncMock(side_effect=[TimeoutError(), TimeoutError(), TimeoutError(), TimeoutError()])
    ):
        events, errors = await inspect_host("api.example.com")
    assert events == []
    assert len(errors) == 2 and errors[0].startswith("HTTPS: TimeoutError") and errors[1].startswith("HTTP: TimeoutError")
    assert adaptar("Web", events, "example.com")["observaciones"] == []


@pytest.mark.anyio
async def test_redireccion_a_otro_host_es_inconclusa_sin_seguirla():
    with patch("app.web_posture._public_addresses", new=AsyncMock(return_value=["8.8.8.8"])), patch(
        "app.web_posture._head", new=AsyncMock(side_effect=[(200, {}, {}), (302, {"location": "https://other.net/"}, {})])
    ):
        events, errors = await inspect_host("api.example.com")
    assert not any(event["check"] == "http_sin_redireccion" for event in events)
    assert errors == ["HTTP: redirección no verificable sin seguir destinos externos"]


def test_web_incluida_en_progreso_al_iniciar():
    from unittest.mock import MagicMock
    from app.scan_service import SOURCE_NAMES, _start_scan
    assert "Web" in SOURCE_NAMES
    client = MagicMock()
    client.rpc.return_value.execute.return_value.data = True
    ids = {name: f"id-{name}" for name in SOURCE_NAMES}
    _start_scan(client, "scan-1", ids)
    assert ids["Web"] in client.rpc.call_args.args[1]["p_fuentes"]


def test_web_confirmado_prevalece_sobre_senal_tls_historica_sin_duplicar():
    active = Obs("web", "asset-api", "subdominio", "api.example.com", "info_host",
                 {"check": "tls_por_expirar", "comprobacion_activa": True,
                  "valid_until": (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()}, "Web", "source-web")
    rule = Regla("near", "CONF-007", "TLS próximo", "configuracion", "baja", 4)
    risk = evaluar_riesgo([active], [rule], {"Web": "completado"})
    assert len(risk.hallazgos) == 1
    assert risk.hallazgos[0].nivel_evidencia == "confirmada"
    assert risk.puntaje.puntaje_global > 0


@pytest.mark.anyio
async def test_web_se_ejecuta_desde_el_flujo_y_aporta_riesgo():
    from app import orchestrators, scan_service
    from app.osint_normalization import adaptar
    from app.risk.modelos import Obs, Regla
    from app.risk.motor import evaluar_riesgo

    settings = SimpleNamespace(
        censys_pat=None, censys_max_ips=10, censys_pause_seconds=1.1, web_enabled=True,
        theharvester_bin="x", theharvester_sources="certspotter", spiderfoot_url="http://x",
        spiderfoot_modules="sfp_dnsresolve", request_timeout_seconds=1,
        process_timeout_seconds=1, spiderfoot_timeout_seconds=1, spiderfoot_poll_seconds=1,
        scan_timeout_seconds=5, scan_max_targets=5, crtsh_retries=1,
        crtsh_timeout_seconds=1, crtsh_total_timeout_seconds=2,
    )
    captured = {}
    def persist(_client, _org, _scan, _source_id, name, _domain, outcome, *_args):
        captured[name] = outcome
        return {"estado": outcome["estado"], "error": outcome.get("error"),
                "observaciones_generadas": len(outcome.get("contenido") or []) if name == "Web" else 0}
    async def inspect(host, timeout):
        return ([{"host": host, "check": "http_sin_redireccion", "status": 200,
                  "validation_mode": "active-authorized-v1"}] if host.startswith("api.")
                else [{"host": host, "check": "tls_verificado",
                       "validation_mode": "active-authorized-v1"}]), []
    with (
        patch.object(orchestrators, "run_crtsh", new=AsyncMock(return_value=orchestrators.RunnerOutput({
            "version": 1, "entries": [], "queries": [{"query": "%.example.com", "status": "ok"}]}))),
        patch.object(orchestrators, "run_theharvester", new=AsyncMock(return_value={"items": [], "runs": []})),
        patch.object(orchestrators, "run_spiderfoot", new=AsyncMock(return_value=[])),
        patch.object(orchestrators, "inspect_host", new=AsyncMock(side_effect=inspect)) as web_probe,
        patch.object(scan_service, "_persist_source", side_effect=persist),
        patch.object(scan_service, "inventory", return_value=[]),
        patch.object(scan_service, "build_coverage", return_value={"objetivos_pendientes": []}),
        patch.object(scan_service, "_finish_scan", return_value=True),
        patch.object(scan_service, "audit"),
        patch.object(scan_service, "calculate_risk_with_retry", new=AsyncMock()) as risk_save,
    ):
        await scan_service.run_scan_job(object(), settings,
            {"id": "scan-1", "organizacion_id": "org-1"},
            {name: name for name in scan_service.SOURCE_NAMES},
            "example.com", targets=["example.com", "api.example.com"], ip_scope="example.com")
    assert web_probe.await_count == 2
    assert {call.args[0] for call in web_probe.await_args_list} == {"example.com", "api.example.com"}
    assert captured["Web"]["estado"] == "completado"
    assert len(captured["Web"]["contenido"]) == 2
    assert len(captured["Web"]["consultas"]) == 2
    risk_save.assert_awaited_once()
    items = adaptar("Web", captured["Web"]["contenido"], "example.com")["observaciones"]
    observations = [Obs(str(i), "asset-api", item["tipo"], item["valor"], item["atributo"],
                        item["datos"], "Web", "source-web") for i, item in enumerate(items)]
    score = evaluar_riesgo(observations,
        [Regla("http", "CONF-008", "HTTP claro", "configuracion", "media", 6)],
        {"Web": "completado"})
    assert [finding.regla_codigo for finding in score.hallazgos] == ["CONF-008"]
    assert score.puntaje.puntaje_global > 0


def test_web_persiste_estado_duracion_y_observaciones():
    from unittest.mock import MagicMock
    from app import scan_service
    client = MagicMock()
    raw = [{"host": "example.com", "check": "tls_verificado",
            "validation_mode": "active-authorized-v1"}]
    summary = {"resultado_crudo_id": "raw-web", "ya_procesado": False,
               "observaciones_generadas": 1, "activos_nuevos": 0,
               "activos_existentes": 1, "observaciones_nuevas": 1,
               "observaciones_duplicadas": 0, "descartadas": {}}
    with patch.object(scan_service, "ingestar_resultado", return_value=summary), patch.object(scan_service, "_execute"):
        stored = scan_service._persist_source(client, "org", "scan", "source-web", "Web", "example.com",
            {"estado": "completado", "contenido": raw, "error": None})
    update = client.table.return_value.update.call_args.args[0]
    assert stored["estado"] == update["estado"] == "completado"
    assert stored["observaciones_generadas"] == update["observaciones_generadas"] == 1
    assert update["resultado_crudo_id"] == "raw-web"
    assert update["finalizado_en"]
