"""Asistente: recorte de historial, armado del prompt y manejo de errores (sin llamar a la API)."""

from types import SimpleNamespace

import pytest

from app.assistant.chat import (
    MAX_MENSAJES,
    SYSTEM_PROMPT,
    AsistenteError,
    AsistenteNoDisponible,
    ClaudeAsistente,
    Mensaje,
    crear_asistente,
    preparar_mensajes,
)


class _Mensajes:
    def __init__(self, texto="Hola", falla=False):
        self.texto = texto
        self.falla = falla
        self.llamadas = []

    def create(self, **kwargs):
        self.llamadas.append(kwargs)
        if self.falla:
            raise RuntimeError("API caída")
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.texto)])


def _asistente(**kwargs):
    fake = SimpleNamespace(messages=_Mensajes(**kwargs))
    return ClaudeAsistente("clave", "claude-haiku-5-5", 500, cliente=fake), fake.messages


def test_recorta_historial_y_empieza_con_usuario():
    mensajes = [Mensaje(role="user" if i % 2 == 0 else "assistant", content=f"m{i}") for i in range(15)]
    resultado = preparar_mensajes(mensajes)
    assert len(resultado) <= MAX_MENSAJES
    assert resultado[0]["role"] == "user"
    assert resultado[-1]["role"] == "user"


def test_rechaza_conversacion_que_no_termina_en_usuario():
    with pytest.raises(ValueError):
        preparar_mensajes([Mensaje(role="user", content="hola"), Mensaje(role="assistant", content="¿qué tal?")])


def test_arma_la_llamada_con_contexto_en_system():
    asistente, api = _asistente(texto="  Respuesta  ")
    texto = asistente.responder("Dominio analizado: empresa-demo.com", [Mensaje(role="user", content="¿Qué significa mi riesgo?")])
    assert texto == "Respuesta"
    llamada = api.llamadas[0]
    assert llamada["model"] == "claude-haiku-5-5"
    assert llamada["max_tokens"] == 500
    assert llamada["system"].startswith(SYSTEM_PROMPT)
    assert "<datos_escaneo>\nDominio analizado: empresa-demo.com\n</datos_escaneo>" in llamada["system"]
    assert llamada["messages"] == [{"role": "user", "content": "¿Qué significa mi riesgo?"}]


def test_falla_de_la_api_se_convierte_en_error_controlado():
    asistente, _ = _asistente(falla=True)
    with pytest.raises(AsistenteError):
        asistente.responder("ctx", [Mensaje(role="user", content="hola")])


def test_sin_api_key_el_asistente_no_esta_disponible():
    settings = SimpleNamespace(anthropic_api_key=None, anthropic_model="claude-haiku-5-5", assistant_max_tokens=500)
    with pytest.raises(AsistenteNoDisponible):
        crear_asistente(settings)