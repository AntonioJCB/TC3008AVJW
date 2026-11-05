"""Pruebas de contrato con el constructor de consultas REAL de postgrest-py.

Los otros tests simulan el cliente completo y por eso no detectan llamadas que
no existen en la versión instalada (p. ej. `.upsert(...).select(...)`). Aquí se
usa el cliente real y solo se simula la red.
"""
import json
import unittest

import httpx
from fastapi import HTTPException
from postgrest import SyncPostgrestClient

from app.ingestion import _save_raw_result
from app.main import SOURCE_NAMES, _start_scan


def cliente(handler):
    client = SyncPostgrestClient("http://postgrest.test", headers={})
    client.session = httpx.Client(
        base_url="http://postgrest.test", transport=httpx.MockTransport(handler)
    )
    return client


class SupabaseContractTest(unittest.TestCase):
    def test_guardar_crudo_usa_upsert_que_ignora_duplicados(self):
        vistas = []

        def handler(request):
            vistas.append(request)
            return httpx.Response(201, json=[{"id": "abc", "estado": "pendiente"}])

        raw_id, estado = _save_raw_result(cliente(handler), "e", "f", [{"x": 1}], "h")

        self.assertEqual((raw_id, estado), ("abc", "pendiente"))
        self.assertIn("resolution=ignore-duplicates", vistas[0].headers["prefer"])
        self.assertIn("on_conflict=escaneo_id%2Cfuente_id%2Chash_contenido", str(vistas[0].url))

    def test_iniciar_escaneo_usa_rpc_atomica(self):
        vistas = []

        def handler(request):
            vistas.append(request)
            return httpx.Response(200, json=True)

        ids = {nombre: f"id-{i}" for i, nombre in enumerate(SOURCE_NAMES)}
        _start_scan(cliente(handler), "1", ids)

        self.assertEqual(len(vistas), 1)
        self.assertEqual(vistas[0].method, "POST")
        self.assertTrue(str(vistas[0].url).endswith("/rpc/iniciar_escaneo"))
        self.assertEqual(json.loads(vistas[0].content), {
            "p_escaneo_id": "1",
            "p_fuentes": [ids[nombre] for nombre in SOURCE_NAMES],
        })

    def test_iniciar_escaneo_ya_reclamado_responde_409(self):
        def handler(request):
            return httpx.Response(200, json=False)

        ids = {nombre: f"id-{i}" for i, nombre in enumerate(SOURCE_NAMES)}
        with self.assertRaises(HTTPException) as caught:
            _start_scan(cliente(handler), "1", ids)
        self.assertEqual(caught.exception.status_code, 409)

    def test_si_falta_rpc_conserva_inicio_anterior(self):
        vistas = []

        def handler(request):
            vistas.append(request)
            if str(request.url).endswith("/rpc/iniciar_escaneo"):
                return httpx.Response(404, json={
                    "code": "PGRST202", "message": "Function not found", "details": None, "hint": None,
                })
            if request.method == "PATCH":
                return httpx.Response(200, json=[{"id": "1"}])
            return httpx.Response(201, json=[])

        ids = {nombre: f"id-{i}" for i, nombre in enumerate(SOURCE_NAMES)}
        _start_scan(cliente(handler), "1", ids)
        self.assertEqual([request.method for request in vistas], ["POST", "PATCH", "POST"])

if __name__ == "__main__":
    unittest.main()
