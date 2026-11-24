import asyncio
import unittest
from unittest.mock import patch

import httpx

from app import orchestrators
from app.orchestrators import OrchestratorSettings, run_all, run_censys
from app.osint_normalization import adaptar
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo

CLIENT = httpx.AsyncClient
IP = "8.8.8.8"
DOMAIN = "empresa.test"
PAT = "censys-token-secreto"


def payload(ip=IP):
    return {"result": {"resource": {"ip": ip, "services": [
        {"port": 22, "transport_protocol": "TCP", "protocol": "SSH",
         "scan_time": "2026-11-20T00:00:00Z", "software": [],
         "vulns": [{"id": "CVE-2024-12345", "severity": "high", "confidence": 0.8}]},
        {"port": 443, "transport_protocol": "TCP", "protocol": "HTTP"},
    ]}}}


def transport(handler):
    return patch.object(orchestrators.httpx, "AsyncClient", lambda **kw: CLIENT(transport=httpx.MockTransport(handler), **kw))


class CensysCollectorTests(unittest.IsolatedAsyncioTestCase):
    def config(self, **kw):
        return OrchestratorSettings(censys_pat=PAT, **kw)

    async def test_pipeline_por_defecto_sustituye_shodan(self):
        with patch.object(orchestrators, "run_crtsh", return_value=[]), patch.object(orchestrators, "run_censys", return_value=[]), patch.object(orchestrators, "run_theharvester", return_value=[]), patch.object(orchestrators, "run_spiderfoot", return_value=[]):
            results = await run_all(DOMAIN, self.config())
        self.assertEqual(set(results), {"crt.sh", "Censys", "theHarvester", "SpiderFoot"})

    async def test_dns_deduplica_y_excluye_ips_privadas_y_reservadas(self):
        records = [(None, None, None, None, (ip, 0)) for ip in [IP, IP, "127.0.0.1", "192.168.1.1", "203.0.113.10", "2606:4700:4700::1111"]]
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=records):
            self.assertEqual(await orchestrators._resolve_censys_ips(DOMAIN), ["2606:4700:4700::1111", IP])

    async def test_sin_pat_no_consulta_dns_ni_api(self):
        with patch.object(orchestrators, "_resolve_censys_ips") as dns:
            with self.assertRaisesRegex(RuntimeError, "CENSYS_PAT"):
                await run_censys(DOMAIN, OrchestratorSettings())
        dns.assert_not_called()

    async def test_lookup_pat_org_y_conservacion_del_json_original(self):
        def handler(request):
            self.assertEqual(str(request.url).split('?')[0], f"https://api.platform.censys.io/v3/global/asset/host/{IP}")
            self.assertEqual(request.headers["Authorization"], f"Bearer {PAT}")
            self.assertEqual(request.headers["Accept"], "application/vnd.censys.api.v3.host.v1+json")
            self.assertEqual(request.url.params["organization_id"], "org-censys")
            self.assertNotIn(PAT, str(request.url))
            return httpx.Response(200, json=payload())

        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(handler):
            out = await run_censys(DOMAIN, self.config(censys_organization_id="org-censys", censys_authorized_ips='{"empresa.test": ["8.8.8.8"]}'))
        self.assertEqual(out.data["hosts"], [payload()])
        self.assertEqual(out.ips_en_alcance, (IP,))

    async def test_free_no_envia_organizacion_y_dns_no_autoriza_servicios(self):
        def handler(request):
            self.assertNotIn("organization_id", request.url.params)
            return httpx.Response(200, json=payload())
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(handler):
            out = await run_censys(DOMAIN, self.config())
        self.assertEqual(out.ips_en_alcance, ())
        normal = adaptar("Censys", out.data, DOMAIN, list(out.ips_en_alcance))
        self.assertFalse(any(o["tipo"] == "servicio" for o in normal["observaciones"]))
        self.assertIn("servicios_sin_ip_autorizada", [x["motivo"] for x in normal["descartadas"]])

    async def test_404_es_sin_registro_no_error(self):
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(lambda r: httpx.Response(404)):
            out = await run_censys(DOMAIN, self.config())
        self.assertEqual(out.data["hosts"], [])

    async def test_errores_de_cuenta_cuota_y_servidor_son_fallos_sin_secretos(self):
        for code in (401, 402, 403, 429, 503):
            with self.subTest(code=code), patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(lambda r: httpx.Response(code, json={"error": PAT})):
                out = await run_all(DOMAIN, self.config(), runners={"Censys": lambda d: run_censys(d, self.config())})
            result = out["Censys"]
            self.assertEqual(result["estado"], "fallido")
            self.assertIn(str(code), result["error"])
            self.assertNotIn(PAT, result["error"])

    async def test_no_consulta_si_limite_implicaria_truncar(self):
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP, "1.1.1.1"]), transport(lambda r: self.fail("No debe consumir créditos")):
            with self.assertRaisesRegex(RuntimeError, "CENSYS_MAX_IPS"):
                await run_censys(DOMAIN, self.config(censys_max_ips=1))

    async def test_pausa_entre_hosts(self):
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP, "1.1.1.1"]), transport(lambda r: httpx.Response(200, json=payload(r.url.path.rsplit('/', 1)[-1]))), patch.object(orchestrators, "_sleep") as sleep:
            await run_censys(DOMAIN, self.config(censys_pause_seconds=1.2))
        sleep.assert_awaited_once_with(1.2)

    async def test_payload_inesperado_ip_distinta_o_truncado_no_es_exito(self):
        for data in ({}, {"result": {"resource": {"ip": "1.1.1.1"}}}, {"result": {"resource": {"ip": IP, "truncated": True}}}, {"result": {"resource": {"ip": IP, "service_count": 2, "services": []}}}):
            with self.subTest(data=data), patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(lambda r: httpx.Response(200, json=data)):
                with self.assertRaisesRegex(ValueError, "formato Platform v3"):
                    await run_censys(DOMAIN, self.config())

    async def test_dns_sin_ip_publica_falla_sin_consumir_creditos(self):
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "IPs públicas"):
                await run_censys(DOMAIN, self.config())

    async def test_valida_configuracion_de_ips(self):
        with self.assertRaisesRegex(ValueError, "CENSYS_AUTHORIZED_IPS"):
            await run_censys(DOMAIN, self.config(censys_authorized_ips="dominio-no-ip"))

    async def test_ips_de_otra_organizacion_no_autorizan_el_dominio_actual(self):
        with patch.object(orchestrators, "_resolve_censys_ips", return_value=[IP]), transport(lambda r: httpx.Response(200, json=payload())):
            out = await run_censys(DOMAIN, self.config(censys_authorized_ips='{"otro.test": ["8.8.8.8"]}'))
        self.assertEqual(out.ips_en_alcance, ())


class CensysNormalizationTests(unittest.TestCase):
    def raw(self):
        return {"hosts": [payload()], "dns": {"dominio": DOMAIN, "ips": [IP]}}

    def test_normalizacion_a_hallazgos_infra_y_puntaje(self):
        normal = adaptar("Censys", self.raw(), DOMAIN, [IP])
        rows = [Obs(str(i), o["valor"], o["tipo"], o["valor"], o["atributo"], o["datos"], "Censys", "f-censys") for i, o in enumerate(normal["observaciones"])]
        rules = [Regla("r1", "INFRA-001", "SSH", "infraestructura", "alta", 15), Regla("r2", "INFRA-003", "CVE", "infraestructura", "media", 8)]
        out = evaluar_riesgo(rows, rules, {"Censys": "completado"})
        self.assertEqual({h.regla_codigo for h in out.hallazgos}, {"INFRA-001", "INFRA-003"})
        self.assertGreater(out.puntaje.puntaje_global, 0)
        cve = next(o for o in normal["observaciones"] if o["atributo"] == "cve")
        self.assertIsNone(cve["datos"]["verificado"])

    def test_443_solo_no_activa_puertos_peligrosos(self):
        raw = self.raw()
        raw["hosts"][0]["result"]["resource"]["services"] = [{"port": 443, "transport_protocol": "TCP"}]
        normal = adaptar("Censys", raw, DOMAIN, [IP])
        self.assertTrue(any(o["valor"] == f"{IP}:443/tcp" for o in normal["observaciones"]))

    def test_ip_ajena_se_descarta_aunque_este_en_allowlist(self):
        raw = self.raw()
        raw["hosts"] = [payload("1.1.1.1")]
        normal = adaptar("Censys", raw, DOMAIN, [IP, "1.1.1.1"])
        self.assertFalse(any(o["tipo"] == "servicio" for o in normal["observaciones"]))
        self.assertIn("fuera_de_alcance", [o["motivo"] for o in normal["descartadas"]])

    def test_no_inventa_tcp_para_quic_ni_acepta_cve_malformada(self):
        raw = self.raw()
        services = raw["hosts"][0]["result"]["resource"]["services"]
        services[0]["vulns"] = [{"id": "CVE-2024-12345-extra"}]
        services[1]["transport_protocol"] = "QUIC"
        normal = adaptar("Censys", raw, DOMAIN, [IP])
        self.assertFalse(any(o["atributo"] == "cve" for o in normal["observaciones"]))
        self.assertFalse(any(o["valor"] == f"{IP}:443/tcp" for o in normal["observaciones"]))
