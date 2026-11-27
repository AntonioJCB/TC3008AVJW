"""Endpoint del asistente: aislamiento, errores controlados y flujo normal (sin Claude ni Supabase reales)."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main
from app.assistant.chat import AsistenteError, AsistenteNoDisponible

URL = "/api/asistente/chat"
BODY = {"mensajes": [{"role": "user", "content": "¿Qué significa mi riesgo?"}]}
SCAN_ID = "11111111-1111-1111-1111-111111111111"
ESCANEO = {"id": SCAN_ID, "estado": "completado", "finalizado_en": "2026-11-18T10:00:00Z"}


class _Falso:
    def __init__(self, texto="Explicación", error=None):
        self.texto = texto
        self.error = error
        self.llamadas = []

    def responder(self, contexto, mensajes):
        self.llamadas.append((contexto, list(mensajes)))
        if self.error:
            raise self.error
        return self.texto


@pytest.fixture
def api():
    falso = _Falso()
    main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-1")
    main.app.dependency_overrides[main.get_asistente] = lambda: falso
    parches = [
        patch.object(main, "_supabase_client", return_value=object()),
        patch.object(
            main, "_get_profile", return_value={"organizacion_id": "mi-org", "rol": "cliente", "esta_activo": True}
        ),
        patch.object(main, "_organization_domain", return_value="empresa-real.com"),
        patch.object(main, "escaneo_mas_reciente", return_value=ESCANEO),
        patch.object(main, "cargar_contexto", return_value="CONTEXTO"),
    ]
    for parche in parches:
        parche.start()
    try:
        yield TestClient(main.app), falso
    finally:
        for parche in parches:
            parche.stop()
        main.app.dependency_overrides.clear()


def test_responde_con_el_ultimo_escaneo(api):
    client, falso = api
    response = client.post(URL, json=BODY)
    assert response.status_code == 200
    assert response.json() == {"respuesta": "Explicación", "escaneo_id": SCAN_ID, "dominio": "empresa-real.com"}
    assert falso.llamadas[0][0] == "CONTEXTO"
    assert falso.llamadas[0][1][0].content == "¿Qué significa mi riesgo?"


def test_sin_escaneos_no_llama_a_la_ia(api):
    client, falso = api
    with patch.object(main, "escaneo_mas_reciente", return_value=None):
        response = client.post(URL, json=BODY)
    assert response.status_code == 200
    assert "Todavía no hay escaneos" in response.json()["respuesta"]
    assert response.json()["escaneo_id"] is None
    assert falso.llamadas == []


def test_escaneo_de_otra_organizacion_da_404(api):
    client, falso = api
    with patch.object(main, "_get_scan", side_effect=HTTPException(status_code=404, detail="No se encontró")):
        response = client.post(URL, json={**BODY, "escaneo_id": SCAN_ID})
    assert response.status_code == 404
    assert falso.llamadas == []


def test_escaneo_en_ejecucion_da_409(api):
    client, falso = api
    with patch.object(main, "_get_scan", return_value={"id": SCAN_ID, "estado": "ejecutando"}):
        response = client.post(URL, json={**BODY, "escaneo_id": SCAN_ID})
    assert response.status_code == 409
    assert falso.llamadas == []


def test_falla_de_la_ia_da_502(api):
    client, falso = api
    falso.error = AsistenteError("falló")
    assert client.post(URL, json=BODY).status_code == 502


def test_conversacion_mal_formada_da_422(api):
    client, falso = api
    falso.error = ValueError("La conversación debe terminar con un mensaje del usuario")
    assert client.post(URL, json=BODY).status_code == 422


def test_lista_de_mensajes_vacia_da_422(api):
    client, _ = api
    assert client.post(URL, json={"mensajes": []}).status_code == 422


def test_sin_api_key_da_503(api):
    client, _ = api
    main.app.dependency_overrides[main.get_asistente] = lambda: None
    with patch.object(main, "get_settings", return_value=SimpleNamespace()), patch.object(
        main, "crear_asistente", side_effect=AsistenteNoDisponible("falta key")
    ):
        response = client.post(URL, json=BODY)
    assert response.status_code == 503


def test_sin_sesion_da_401():
    assert TestClient(main.app).post(URL, json=BODY).status_code == 401