import asyncio
import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.orchestrators import OrchestratorSettings, run_all
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


@pytest.mark.anyio
async def test_dos_subdominios_web_y_fuente_fallida_puntuan_solo_riesgos():
    async def crtsh(target):
        return [{"name_value": "api.example.com\nshop.example.com"}] if target == "example.com" else []

    async def web(target):
        check = "http_sin_redireccion" if target == "api.example.com" else "tls_invalido"
        return [{"host": target, "check": check}] if target != "example.com" else [{"host": target, "check": "tls_verificado"}]

    async def shodan(_target):
        raise RuntimeError("sin plan")

    results = await run_all(
        "example.com", OrchestratorSettings(),
        runners={"crt.sh": crtsh, "Web": web, "Shodan": shodan},
        targets=["example.com"], max_targets=3,
    )
    items = adaptar("Web", results["Web"]["contenido"], "example.com")["observaciones"]
    observations = [
        Obs(str(i), f"asset-{item['valor']}", item["tipo"], item["valor"],
            item["atributo"], item["datos"], "Web", "source-web")
        for i, item in enumerate(items)
    ]
    rules = [
        Regla("invalid", "CONF-006", "TLS inválido", "configuracion", "media", 12),
        Regla("http", "CONF-008", "HTTP claro", "configuracion", "media", 6),
    ]
    risk = evaluar_riesgo(observations, rules, {"Web": "completado", "Shodan": "fallido"})
    assert risk.hallazgos == [] and risk.puntaje.puntaje_global == 0
    assert risk.puntaje.es_parcial
    assert adaptar("Web", [{"host": "other.net", "check": "tls_invalido"}], "example.com")["observaciones"] == []
