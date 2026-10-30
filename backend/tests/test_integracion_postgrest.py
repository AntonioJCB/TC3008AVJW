"""Flujo completo contra una base REAL (Supabase de desarrollo o PostgREST local).

Se omite si no están definidas estas variables de entorno:
  BAXTERSEC_TEST_POSTGREST_URL    p. ej. https://TU-PROYECTO.supabase.co/rest/v1
  BAXTERSEC_TEST_SERVICE_KEY      la service_role key (solo para pruebas locales)
  BAXTERSEC_TEST_USER_ID          id de un usuario admin/analista con organización
  BAXTERSEC_TEST_AUTORIZACION_ID  id de una autorización vigente de esa organización
  BAXTERSEC_TEST_OTRO_USUARIO_ID  (opcional) usuario de OTRA organización

ADVERTENCIA: escribe escaneos, activos y hallazgos de verdad. Usa un proyecto de
desarrollo, nunca el de producción. Las fuentes externas se simulan: no hay red.
"""
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from postgrest import SyncPostgrestClient

from app import main
from app.orchestrators import RunnerOutput

URL = os.getenv("BAXTERSEC_TEST_POSTGREST_URL")
KEY = os.getenv("BAXTERSEC_TEST_SERVICE_KEY")
USER = os.getenv("BAXTERSEC_TEST_USER_ID")
AUTORIZACION = os.getenv("BAXTERSEC_TEST_AUTORIZACION_ID")
OTRO = os.getenv("BAXTERSEC_TEST_OTRO_USUARIO_ID")


@unittest.skipUnless(URL and KEY and USER and AUTORIZACION, "Configura BAXTERSEC_TEST_* para correr la prueba de integración")
class FlujoCompletoTests(unittest.TestCase):
    parcial_id = completo_id = None

    @classmethod
    def setUpClass(cls):
        cls.db = SyncPostgrestClient(URL, headers={"apikey": KEY, "Authorization": f"Bearer {KEY}"})
        perfil = cls.db.table("usuarios").select("organizacion_id").eq("id", USER).limit(1).execute().data[0]
        org = cls.db.table("organizaciones").select("dominio_principal").eq("id", perfil["organizacion_id"]).limit(1).execute().data[0]
        cls.domain = org["dominio_principal"]
        cls.usuario_actual = USER
        settings = SimpleNamespace(
            shodan_api_key="llave-secreta-123", theharvester_bin="x", theharvester_sources="x", spiderfoot_url="http://x",
            request_timeout_seconds=5, process_timeout_seconds=5, spiderfoot_timeout_seconds=5, spiderfoot_poll_seconds=1,
            scan_timeout_seconds=30, crtsh_retries=1, shodan_max_ips=2, shodan_pause_seconds=0,
        )
        cls.parches = [
            patch.object(main, "get_settings", return_value=settings),
            patch.object(main, "_supabase_client", return_value=cls.db),
        ]
        for p in cls.parches:
            p.start()
        main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id=cls.usuario_actual)
        main.app.dependency_overrides[main.get_runners] = lambda: cls.runners
        cls.runners = cls.construir_runners(shodan_funciona=False)
        cls.http = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        main.app.dependency_overrides.clear()
        for p in cls.parches:
            p.stop()

    @classmethod
    def construir_runners(cls, shodan_funciona):
        ahora = datetime.now(timezone.utc)
        fecha = lambda dias: (ahora + timedelta(days=dias)).strftime("%Y-%m-%dT%H:%M:%S")
        d = cls.domain

        def cert(i, nombres, hasta):
            return {"id": i, "issuer_name": "CN=Demo CA", "common_name": nombres.split("\n")[0], "name_value": nombres,
                    "serial_number": f"serie{i}", "not_before": fecha(-60), "not_after": fecha(hasta), "entry_timestamp": fecha(-60)}

        async def crtsh(domain):
            return [cert(1, f"dev.{d}", -10), cert(2, f"api.{d}", 12), cert(3, f"www.{d}", 100), cert(4, "tercero.invalid", 50)]

        async def shodan(domain):
            if not shodan_funciona:
                request = httpx.Request("GET", "https://api.shodan.io/shodan/host/203.0.113.10?key=llave-secreta-123")
                raise httpx.HTTPStatusError("x", request=request, response=httpx.Response(403, request=request))
            host = {"ip_str": "203.0.113.10", "hostnames": [f"dev.{d}"], "domains": [d], "asn": "AS1", "org": "Hosting",
                    "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.4", "vulns": {"CVE-2018-15473": {"verified": False}}},
                             {"port": 5432, "transport": "tcp", "product": "PostgreSQL"}, {"port": 443, "transport": "tcp", "product": "nginx"}]}
            return RunnerOutput([host], ("203.0.113.10",))

        async def theharvester(domain):
            return {"hosts": [f"dev.{d}:203.0.113.10", d], "ips": [], "emails": [f"contacto@{d}", f"ventas@{d}", "externo@otro.net"], "asns": []}

        async def spiderfoot(domain):
            return [
                {"event_type": "TCP_PORT_OPEN", "data": "203.0.113.10:22", "module": "sfp_portscan_tcp", "source_data": "203.0.113.10"},
                {"event_type": "EMAILADDR", "data": f"contacto@{d}", "module": "sfp_email", "source_data": d},
            ]

        return {"crt.sh": crtsh, "Shodan": shodan, "theHarvester": theharvester, "SpiderFoot": spiderfoot}

    def crear_y_ejecutar(self):
        creado = self.http.post("/api/escaneos", json={"autorizacion_id": AUTORIZACION})
        self.assertEqual(creado.status_code, 201, creado.text)
        scan_id = creado.json()["escaneo_id"]
        self.assertEqual(creado.json()["dominio"], self.domain)
        ejecutado = self.http.post(f"/api/escaneos/{scan_id}/ejecutar")
        self.assertEqual(ejecutado.status_code, 202, ejecutado.text)
        self.assertEqual(ejecutado.json()["estado"], "ejecutando")  # respondió antes de terminar
        return scan_id

    # --- Escaneo con Shodan caído -------------------------------------------------

    def test_01_una_fuente_falla_las_otras_siguen_y_queda_incompleto(self):
        type(self).parcial_id = scan_id = self.crear_y_ejecutar()
        detalle = self.http.get(f"/api/escaneos/{scan_id}")
        self.assertEqual(detalle.status_code, 200, detalle.text)
        d = detalle.json()
        self.assertEqual(d["estado"], "incompleto")
        self.assertEqual(d["fuentes_fallidas"], ["Shodan"])
        self.assertEqual(d["fuentes_ok"], ["crt.sh", "theHarvester", "SpiderFoot"])
        self.assertIn("Fallaron: Shodan (HTTP 403 from api.shodan.io)", d["mensaje"])
        self.assertNotIn("llave-secreta-123", str(d))
        por_fuente = {f["fuente"]: f for f in d["fuentes"]}
        self.assertEqual(por_fuente["Shodan"]["estado"], "fallido")
        self.assertGreater(por_fuente["crt.sh"]["observaciones_nuevas"], 0)
        self.assertEqual(por_fuente["crt.sh"]["descartadas"].get("fuera_de_alcance"), 1)  # tercero.invalid

    def test_02_el_riesgo_es_parcial_y_dice_que_fuente_falto(self):
        r = self.http.get(f"/api/escaneos/{self.parcial_id}/riesgo")
        self.assertEqual(r.status_code, 200, r.text)
        riesgo = r.json()
        self.assertTrue(riesgo["es_parcial"])
        self.assertEqual(riesgo["fuentes_faltantes"], ["Shodan"])
        # SpiderFoot sí vio el puerto 22, así que INFRA-001 se evalúa y se cumple
        self.assertIn("INFRA-001", riesgo["cobertura"]["evaluadas"])
        self.assertGreater(riesgo["configuracion"], 0)  # certificado vencido + por vencer
        self.assertGreater(riesgo["puntaje_global"], 0)

    def test_03_hallazgos_con_evidencia_y_corroboracion(self):
        hallazgos = self.http.get(f"/api/escaneos/{self.parcial_id}/hallazgos").json()
        por_regla = {}
        for h in hallazgos:
            por_regla.setdefault(h["regla_codigo"], []).append(h)
        self.assertEqual(sorted(por_regla), ["CONF-001", "CONF-002", "IDEN-003", "INFRA-001"])
        self.assertEqual(por_regla["CONF-001"][0]["activo_valor"], f"dev.{self.domain}")
        ssh = por_regla["INFRA-001"][0]
        self.assertEqual(ssh["fuentes"], ["SpiderFoot"])  # Shodan falló: una sola fuente
        self.assertEqual(ssh["confianza"], 0.7)
        correos = {h["activo_valor"]: h for h in por_regla["IDEN-003"]}
        self.assertEqual(correos[f"contacto@{self.domain}"]["fuentes"], ["SpiderFoot", "theHarvester"])  # corroborado
        self.assertEqual(correos[f"contacto@{self.domain}"]["confianza"], 0.95)
        self.assertNotIn("externo@otro.net", correos)  # fuera de alcance
        severidades = [h["severidad"] for h in hallazgos]
        self.assertEqual(severidades, sorted(severidades, key=["critica", "alta", "media", "baja"].index))

    def test_04_recalcular_es_idempotente_y_respeta_el_triage(self):
        antes = self.http.get(f"/api/escaneos/{self.parcial_id}/hallazgos").json()
        self.db.table("hallazgos").update({"estado": "aceptado"}).eq("id", antes[0]["id"]).execute()
        recalculado = self.http.post(f"/api/escaneos/{self.parcial_id}/riesgo/recalcular")
        self.assertEqual(recalculado.status_code, 200, recalculado.text)
        despues = self.http.get(f"/api/escaneos/{self.parcial_id}/hallazgos").json()
        self.assertEqual(len(despues), len(antes))  # sin duplicados
        self.assertEqual({h["id"]: h["estado"] for h in despues}[antes[0]["id"]], "aceptado")  # triage intacto

    # --- Escaneo con las cuatro fuentes funcionando -----------------------------

    def test_05_con_todas_las_fuentes_queda_completado_y_el_riesgo_deja_de_ser_parcial(self):
        type(self).runners = self.construir_runners(shodan_funciona=True)
        type(self).completo_id = scan_id = self.crear_y_ejecutar()
        d = self.http.get(f"/api/escaneos/{scan_id}").json()
        self.assertEqual((d["estado"], d["fuentes_fallidas"]), ("completado", []))
        self.assertIn("las 4 fuentes terminaron correctamente", d["mensaje"])
        riesgo = d["riesgo"]
        self.assertFalse(riesgo["es_parcial"])
        self.assertEqual(riesgo["fuentes_faltantes"], [])
        parcial = self.http.get(f"/api/escaneos/{self.parcial_id}/riesgo").json()
        self.assertGreater(riesgo["infraestructura"], parcial["infraestructura"])  # ahora Shodan aporta DB y CVE
        reglas = {h["regla_codigo"] for h in self.http.get(f"/api/escaneos/{scan_id}/hallazgos").json()}
        self.assertTrue({"INFRA-002", "INFRA-003"} <= reglas, reglas)  # PostgreSQL expuesto y CVE
        ssh = [h for h in self.http.get(f"/api/escaneos/{scan_id}/hallazgos").json() if h["regla_codigo"] == "INFRA-001"][0]
        self.assertEqual((ssh["fuentes"], ssh["confianza"]), (["Shodan", "SpiderFoot"], 0.85))  # dos fuentes

    def test_05b_la_bitacora_registra_quien_escaneo_y_que_fuente_fallo(self):
        filas = self.db.table("bitacora_auditoria").select("accion, usuario_id, detalle").eq("entidad_id", self.parcial_id).execute().data
        por_accion = {f["accion"]: f for f in filas}
        self.assertEqual(set(por_accion), {"escaneo_creado", "escaneo_finalizado"})
        self.assertEqual(por_accion["escaneo_creado"]["usuario_id"], USER)
        cierre = por_accion["escaneo_finalizado"]["detalle"]
        self.assertEqual(cierre["estado"], "incompleto")
        self.assertEqual(list(cierre["fuentes_fallidas"]), ["Shodan"])
        self.assertNotIn("llave-secreta-123", str(filas))

    def test_06_el_historial_lista_ambos_escaneos_con_su_puntaje(self):
        escaneos = {e["escaneo_id"]: e for e in self.http.get("/api/escaneos").json()}
        self.assertEqual(escaneos[self.parcial_id]["estado"], "incompleto")
        self.assertTrue(escaneos[self.parcial_id]["es_parcial"])
        self.assertEqual(escaneos[self.completo_id]["estado"], "completado")
        self.assertIsNotNone(escaneos[self.completo_id]["puntaje_global"])
        self.assertEqual(escaneos[self.completo_id]["dominio"], self.domain)

    # --- Errores y permisos -------------------------------------------------------

    def test_07_errores_claros(self):
        inexistente = "99999999-9999-9999-9999-999999999999"
        self.assertEqual(self.http.get(f"/api/escaneos/{inexistente}").status_code, 404)  # no 502
        self.assertEqual(self.http.post(f"/api/escaneos/{self.completo_id}/ejecutar").status_code, 409)  # ya ejecutado
        self.assertEqual(self.http.post("/api/escaneos", json={"autorizacion_id": inexistente}).status_code, 403)
        self.assertEqual(self.http.get(f"/api/escaneos/{inexistente}/riesgo").status_code, 404)
        pendiente = self.http.post("/api/escaneos", json={"autorizacion_id": AUTORIZACION}).json()["escaneo_id"]
        self.assertEqual(self.http.post(f"/api/escaneos/{pendiente}/riesgo/recalcular").status_code, 409)  # aún no corre
        self.assertEqual(self.http.get(f"/api/escaneos/{pendiente}").json()["mensaje"], "El escaneo está pendiente de ejecución.")

    @unittest.skipUnless(OTRO, "Define BAXTERSEC_TEST_OTRO_USUARIO_ID para probar el aislamiento entre organizaciones")
    def test_08_otra_organizacion_no_ve_nada(self):
        type(self).usuario_actual = OTRO
        try:
            for ruta in ("", "/riesgo", "/hallazgos", "/fuentes"):
                self.assertEqual(self.http.get(f"/api/escaneos/{self.completo_id}{ruta}").status_code, 404, ruta)
            self.assertEqual(self.http.post("/api/escaneos", json={"autorizacion_id": AUTORIZACION}).status_code, 403)
            self.assertNotIn(self.completo_id, [e["escaneo_id"] for e in self.http.get("/api/escaneos").json()])
        finally:
            type(self).usuario_actual = USER


if __name__ == "__main__":
    unittest.main()
