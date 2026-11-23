import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs
from unittest.mock import patch

import httpx

from app import orchestrators
from app.orchestrators import OrchestratorSettings, RunnerOutput, run_all, run_crtsh, run_shodan

REAL_ASYNC_CLIENT = httpx.AsyncClient


def with_transport(handler):
    """Sustituye el cliente HTTP de orchestrators por uno que responde `handler` (sin red)."""
    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return REAL_ASYNC_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)

    return patch.object(orchestrators.httpx, "AsyncClient", factory)


class Pausas:
    """Registra las esperas en lugar de dormir de verdad."""

    def __init__(self):
        self.valores = []

    async def __call__(self, segundos):
        self.valores.append(segundos)


class RunAllCallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_on_result_se_llama_apenas_termina_cada_fuente(self):
        orden = []

        async def rapida(domain):
            return "rapida"

        async def lenta(domain):
            await asyncio.sleep(0.05)
            return "lenta"

        async def on_result(nombre, resultado):
            orden.append(nombre)

        await run_all("ejemplo.com", OrchestratorSettings(), runners={"lenta": lenta, "rapida": rapida}, on_result=on_result)
        self.assertEqual(orden, ["rapida", "lenta"])  # la rápida se guarda sin esperar a la lenta

    async def test_fallo_en_on_result_no_afecta_a_las_demas(self):
        async def fuente(domain):
            return "ok"

        async def on_result(nombre, resultado):
            raise RuntimeError("falló al guardar")

        r = await run_all("ejemplo.com", OrchestratorSettings(), runners={"a": fuente, "b": fuente}, on_result=on_result)
        self.assertEqual({k: v["estado"] for k, v in r.items()}, {"a": "completado", "b": "completado"})

    async def test_tiempo_maximo_marca_la_fuente_como_fallida_y_las_otras_siguen(self):
        async def cuelga(domain):
            await asyncio.sleep(10)

        async def rapida(domain):
            return "ok"

        r = await run_all("ejemplo.com", OrchestratorSettings(), runners={"cuelga": cuelga, "rapida": rapida}, timeout_seconds=0.05)
        self.assertEqual(r["cuelga"]["estado"], "fallido")
        self.assertIn("tiempo máximo", r["cuelga"]["error"])
        self.assertEqual(r["rapida"]["estado"], "completado")

    async def test_runner_output_lleva_las_ips_del_objetivo(self):
        async def shodan(domain):
            return RunnerOutput([{"ip_str": "203.0.113.10"}], ("203.0.113.10",))

        r = await run_all("ejemplo.com", OrchestratorSettings(), runners={"Shodan": shodan})
        self.assertEqual(r["Shodan"]["contenido"], [{"ip_str": "203.0.113.10"}])
        self.assertEqual(r["Shodan"]["ips_en_alcance"], ["203.0.113.10"])


class CrtshTests(unittest.IsolatedAsyncioTestCase):
    async def test_configuracion_deshabilitada_no_invoca_crtsh(self):
        with (
            patch.object(orchestrators, "run_crtsh") as crt,
            patch.object(orchestrators, "run_theharvester", return_value=[]),
            patch.object(orchestrators, "run_spiderfoot", return_value=[]),
        ):
            result = await run_all("ejemplo.com", OrchestratorSettings(crtsh_enabled=False))
        self.assertEqual(set(result), {"theHarvester", "SpiderFoot"})
        crt.assert_not_called()

    async def test_fallo_wildcard_no_multiplica_consultas_por_subdominio(self):
        llamados = []
        async def failed(target):
            llamados.append(target)
            return RunnerOutput({
                "version": 1, "entries": [], "covered_targets": [target],
                "queries": [{"query": f"%.{target}", "status": "error", "error": "HTTP 429 from crt.sh"}],
            }, error="HTTP 429 from crt.sh", failed=True)
        result = (await run_all(
            "ejemplo.com", OrchestratorSettings(), runners={"crt.sh": failed},
            targets=["ejemplo.com", "api.ejemplo.com", "www.ejemplo.com"],
        ))["crt.sh"]
        self.assertEqual(llamados, ["ejemplo.com"])
        self.assertEqual(result["estado"], "fallido")
        self.assertEqual([row["estado"] for row in result["consultas"]], ["fallido"] * 3)
        self.assertTrue(all("wildcard" in (row.get("error") or "")
                            for row in result["consultas"][1:]))

    async def test_wildcard_valido_conserva_observaciones_y_cubre_subdominios(self):
        llamados = []
        entry = {"id": 7, "name_value": "api.ejemplo.com"}
        async def completed(target):
            llamados.append(target)
            return RunnerOutput({
                "version": 1, "entries": [entry], "covered_targets": [target],
                "queries": [{"query": f"%.{target}", "status": "ok", "entries": 1}],
            })
        result = (await run_all(
            "ejemplo.com", OrchestratorSettings(), runners={"crt.sh": completed},
            targets=["ejemplo.com", "api.ejemplo.com", "www.ejemplo.com"],
        ))["crt.sh"]
        self.assertEqual(llamados, ["ejemplo.com"])
        self.assertEqual(result["contenido"]["entries"], [entry])
        self.assertEqual(result["contenido"]["covered_targets"], [
            "ejemplo.com", "api.ejemplo.com", "www.ejemplo.com",
        ])
        self.assertEqual([row["estado"] for row in result["consultas"]], ["completado"] * 3)

    async def test_reintenta_con_espera_creciente_y_termina_bien(self):
        respuestas = iter([httpx.Response(502), httpx.Response(200, json=[{"id": 1}]), httpx.Response(200, json=[])])
        pausas = Pausas()
        with with_transport(lambda request: next(respuestas)), patch.object(orchestrators, "_sleep", pausas):
            datos = await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=3))
        self.assertEqual(datos.data["entries"], [{"id": 1}])
        self.assertEqual(pausas.valores, [2])

    async def test_agota_los_reintentos_y_falla_sin_exponer_la_url(self):
        pausas = Pausas()
        with with_transport(lambda request: httpx.Response(503)), patch.object(orchestrators, "_sleep", pausas):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=3))
        self.assertEqual(len(pausas.valores), 2)
        self.assertTrue(result.failed)
        self.assertIn("503", result.error)
        self.assertEqual(len(result.data["queries"]), 2)

    async def test_cuerpo_vacio_no_equivale_a_sin_certificados(self):
        with with_transport(lambda request: httpx.Response(200, text="")):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings())
        self.assertTrue(result.failed)
        self.assertIn("sin cuerpo JSON", result.error)

    async def test_json_vacio_si_es_resultado_valido(self):
        with with_transport(lambda request: httpx.Response(200, json=[])):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings())
        self.assertEqual(result.data["entries"], [])
        self.assertEqual([row["status"] for row in result.data["queries"]], ["ok", "ok"])

    async def test_crtsh_usa_su_propio_tiempo_de_espera(self):
        limites = []

        def handler(request):
            limites.append(request.extensions["timeout"]["read"])
            return httpx.Response(200, json=[])

        with with_transport(handler):
            await run_crtsh("ejemplo.com", OrchestratorSettings(request_timeout_seconds=5, crtsh_timeout_seconds=60))
        self.assertEqual(limites, [15, 15])

    async def test_un_error_4xx_no_se_reintenta(self):
        llamadas = []

        def handler(request):
            llamadas.append(1)
            return httpx.Response(400)

        with with_transport(handler), patch.object(orchestrators, "_sleep", Pausas()):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings())
        self.assertTrue(result.failed)
        self.assertEqual(len(llamadas), 2)

    async def test_respeta_retry_after_en_limite_de_consultas(self):
        pausas = Pausas()
        respuestas = iter([
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, json=[]), httpx.Response(200, json=[]),
        ])
        with with_transport(lambda request: next(respuestas)), patch.object(orchestrators, "_sleep", pausas):
            self.assertEqual((await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=2))).data["entries"], [])
        self.assertEqual(pausas.valores, [7])

    async def test_espera_mas_cuando_429_no_incluye_retry_after(self):
        pausas = Pausas()
        respuestas = iter([httpx.Response(429), httpx.Response(200, json=[]), httpx.Response(200, json=[])])
        with with_transport(lambda request: next(respuestas)), patch.object(orchestrators, "_sleep", pausas):
            self.assertEqual((await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=2))).data["entries"], [])
        self.assertEqual(pausas.valores, [5])

    async def test_retry_after_mayor_al_presupuesto_no_reintenta(self):
        pausas = Pausas()
        llamadas = []
        def handler(request):
            llamadas.append(str(request.url.params.get("q")))
            return httpx.Response(429, headers={"Retry-After": "120"})
        with with_transport(handler), patch.object(orchestrators, "_sleep", pausas):
            result = await run_crtsh(
                "ejemplo.com", OrchestratorSettings(crtsh_total_timeout_seconds=10)
            )
        self.assertTrue(result.failed)
        self.assertEqual(llamadas, ["%.ejemplo.com", "ejemplo.com"])
        self.assertEqual(pausas.valores, [])

    async def test_sin_subdominios_consulta_certificado_del_dominio_exacto(self):
        consultas = []

        def handler(request):
            consultas.append(str(request.url.params.get("q")))
            return httpx.Response(200, json=[] if len(consultas) == 1 else [{"name_value": "ejemplo.com"}])

        with with_transport(handler):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings())
        self.assertEqual(consultas, ["%.ejemplo.com", "ejemplo.com"])
        self.assertEqual(result.data["entries"][0]["name_value"], "ejemplo.com")

    async def test_fallo_de_una_consulta_conserva_la_otra_y_se_reporta_parcial(self):
        def handler(request):
            return (httpx.Response(502) if request.url.params["q"].startswith("%")
                    else httpx.Response(200, json=[{"name_value": "ejemplo.com"}]))

        with with_transport(handler), patch.object(orchestrators, "_sleep", Pausas()):
            result = await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=1))
        self.assertEqual(result.data["entries"], [{"name_value": "ejemplo.com"}])
        self.assertEqual([row["status"] for row in result.data["queries"]], ["error", "ok"])
        self.assertIn("502", result.error)


class ShodanTests(unittest.IsolatedAsyncioTestCase):
    def ajustes(self, **extra):
        return OrchestratorSettings(shodan_api_key="llave-secreta-123", **extra)

    async def test_sin_llave_falla_con_mensaje_claro(self):
        with self.assertRaisesRegex(RuntimeError, "SHODAN_API_KEY"):
            await run_shodan("ejemplo.com", OrchestratorSettings())

    async def test_ip_autorizada_se_consulta_directamente_sin_resolucion_dns(self):
        paths = []

        def handler(request):
            paths.append(request.url.path)
            return httpx.Response(200, json={"ip_str": "8.8.8.8", "data": []})

        with with_transport(handler):
            result = await run_shodan("8.8.8.8", self.ajustes())
        self.assertEqual(paths, ["/shodan/host/8.8.8.8"])
        self.assertEqual(result.ips_en_alcance, ("8.8.8.8",))

    async def test_resuelve_el_dominio_y_consulta_cada_ip_con_pausa(self):
        vistas = []

        def handler(request):
            vistas.append(request.url.path)
            if request.url.path == "/dns/resolve":
                return httpx.Response(200, json={"ejemplo.com": "203.0.113.10", "otro.ejemplo.com": "203.0.113.11", "x": None})
            if request.url.path == "/shodan/host/203.0.113.10":
                return httpx.Response(200, json={"ip_str": "203.0.113.10", "data": []})
            return httpx.Response(404, json={"error": "No information available for that IP."})

        pausas = Pausas()
        with with_transport(handler), patch.object(orchestrators, "_sleep", pausas):
            salida = await run_shodan("ejemplo.com", self.ajustes())
        self.assertEqual(vistas, ["/dns/resolve", "/shodan/host/203.0.113.10", "/shodan/host/203.0.113.11"])
        self.assertEqual(salida.data, [{"ip_str": "203.0.113.10", "data": []}])  # el 404 se omite
        self.assertEqual(salida.ips_en_alcance, ("203.0.113.10", "203.0.113.11"))
        self.assertEqual(pausas.valores, [1.1])

    async def test_respeta_el_maximo_de_ips(self):
        resueltos = {f"h{i}.ejemplo.com": f"203.0.113.{i}" for i in range(1, 8)}
        consultadas = []

        def handler(request):
            if request.url.path == "/dns/resolve":
                return httpx.Response(200, json=resueltos)
            consultadas.append(request.url.path)
            return httpx.Response(404)

        with with_transport(handler), patch.object(orchestrators, "_sleep", Pausas()):
            salida = await run_shodan("ejemplo.com", self.ajustes(shodan_max_ips=3))
        self.assertEqual(len(consultadas), 3)
        self.assertEqual(len(salida.ips_en_alcance), 3)

    async def test_error_de_plan_no_filtra_la_llave(self):
        def handler(request):
            return httpx.Response(403, json={"error": "Requires membership"})

        with with_transport(handler):
            outcome = (await run_all("ejemplo.com", self.ajustes(), runners={"Shodan": lambda d: run_shodan(d, self.ajustes())}))["Shodan"]
        self.assertEqual(outcome["estado"], "fallido")
        self.assertIn("Membership", outcome["error"])
        self.assertNotIn("llave-secreta-123", outcome["error"])

    async def test_sin_ips_devuelve_lista_vacia_sin_fallar(self):
        with with_transport(lambda request: httpx.Response(200, json={"ejemplo.com": None})):
            salida = await run_shodan("ejemplo.com", self.ajustes())
        self.assertEqual((salida.data, salida.ips_en_alcance), ([], ()))


class SpiderFootTests(unittest.IsolatedAsyncioTestCase):
    async def test_servicio_desconectado_da_instruccion(self):
        def disconnected(request):
            raise httpx.ConnectError("connection refused", request=request)

        with with_transport(disconnected):
            outcome = (await run_all("ejemplo.com", OrchestratorSettings(), runners={"SpiderFoot": lambda d: orchestrators.run_spiderfoot(d, OrchestratorSettings())}))["SpiderFoot"]
        self.assertIn("Inicia el servicio", outcome["error"])


    async def test_inicia_modulos_acotados_y_exporta_el_escaneo(self):
        rutas = []

        def handler(request):
            rutas.append(request.url.path)
            if request.url.path == "/startscan":
                form = parse_qs(request.content.decode())
                if form.get("modulelist") != [orchestrators.DEFAULT_SPIDERFOOT_MODULES]:
                    return httpx.Response(200, json=["ERROR", "Incorrect usage: no modules specified for scan."])
                self.assertNotIn("sfp_stevenblack_hosts", form["modulelist"][0])
                return httpx.Response(200, json=["SUCCESS", "scan-123"])
            self.assertEqual(request.url.params.get("id") or request.url.params.get("ids"), "scan-123")
            if request.url.path == "/scanstatus":
                return httpx.Response(200, json=[None, None, None, None, None, "FINISHED"])
            return httpx.Response(200, json=[{"data": "ejemplo.com"}])

        with with_transport(handler):
            datos = await orchestrators.run_spiderfoot("ejemplo.com", OrchestratorSettings())
        self.assertEqual(datos.data[0], {"data": "ejemplo.com"})
        commoncrawl = orchestrators.passive_reports(datos.data[1:])
        self.assertEqual(len(commoncrawl), 1)
        self.assertEqual(commoncrawl[0]["provider"], "common_crawl")
        self.assertEqual(commoncrawl[0]["status"], "unavailable")
        self.assertTrue(commoncrawl[0]["disabled"])
        self.assertTrue(datos.failed)
        self.assertIn("Sin constancia", datos.error)
        self.assertEqual(rutas, ["/startscan", "/scanstatus", "/scanexportjsonmulti"])

    async def test_fuentes_habilitadas_sanas_completan_y_commoncrawl_queda_no_evaluado(self):
        modules = {
            "sfp_baxter_dns_doh": "google_dns_doh",
            "sfp_baxter_urlscan": "urlscan",
            "sfp_baxter_rdap": "rdap",
        }
        payload = [{
            "event_type": "RAW_RIR_DATA",
            "data": json.dumps({
                "profile": "baxter-passive-v1", "provider": provider,
                "target": "ejemplo.com", "status": "empty", "query": "fixture",
                "events": [], "results": 0, "checked_at": "2026-11-20T00:00:00Z",
                "limitations": [],
            }),
            "module": module, "scan_target": "ejemplo.com",
            "source_data": "ejemplo.com", "false_positive": 0,
        } for module, provider in modules.items()]

        def handler(request):
            if request.url.path == "/startscan":
                configured = parse_qs(request.content.decode())["modulelist"][0]
                self.assertNotIn("sfp_baxter_commoncrawl", configured)
                return httpx.Response(200, json=["SUCCESS", "scan-healthy"])
            if request.url.path == "/scanstatus":
                return httpx.Response(200, json=[None, None, None, None, None, "FINISHED"])
            return httpx.Response(200, json=payload)

        with with_transport(handler):
            output = await orchestrators.run_spiderfoot("ejemplo.com", OrchestratorSettings())
        summaries = orchestrators.passive_reports(output.data)
        self.assertFalse(output.failed)
        self.assertIsNone(output.error)
        self.assertEqual(
            {report["provider"]: report["status"] for report in summaries},
            {"google_dns_doh": "empty", "urlscan": "empty", "rdap": "empty",
             "common_crawl": "unavailable"},
        )

    async def test_cancelacion_solicita_detener_el_escaneo_remoto(self):
        polling = asyncio.Event()
        routes = []

        def handler(request):
            routes.append(request.url.path)
            if request.url.path == "/startscan":
                return httpx.Response(200, json=["SUCCESS", "scan-123"])
            if request.url.path == "/scanstatus":
                polling.set()
                return httpx.Response(200, json=[None, None, None, None, None, "RUNNING"])
            self.assertEqual(parse_qs(request.content.decode()).get("id"), ["scan-123"])
            return httpx.Response(200, json="")

        with with_transport(handler):
            job = asyncio.create_task(orchestrators.run_spiderfoot(
                "ejemplo.com", OrchestratorSettings(spiderfoot_poll_seconds=30)
            ))
            await asyncio.wait_for(polling.wait(), timeout=2)
            job.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await job
        self.assertEqual(routes, ["/startscan", "/scanstatus", "/stopscan"])

    async def test_cancelacion_durante_startscan_detiene_el_trabajo_remoto(self):
        starting = asyncio.Event()
        release = asyncio.Event()
        routes = []

        async def handler(request):
            routes.append(request.url.path)
            if request.url.path == "/startscan":
                starting.set()
                await release.wait()
                return httpx.Response(200, json=["SUCCESS", "scan-early"])
            self.assertEqual(parse_qs(request.content.decode()).get("id"), ["scan-early"])
            return httpx.Response(200, json="")

        with with_transport(handler):
            job = asyncio.create_task(orchestrators.run_spiderfoot("ejemplo.com", OrchestratorSettings()))
            await asyncio.wait_for(starting.wait(), timeout=2)
            job.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(job, timeout=2)
        self.assertEqual(routes, ["/startscan", "/stopscan"])

    async def test_timeout_de_startscan_recupera_id_y_detiene_el_trabajo(self):
        routes = []
        scan_name = ""

        def handler(request):
            nonlocal scan_name
            routes.append(request.url.path)
            if request.url.path == "/startscan":
                scan_name = parse_qs(request.content.decode())["scanname"][0]
                raise httpx.ReadTimeout("sin respuesta", request=request)
            if request.url.path == "/scanlist":
                return httpx.Response(200, json=[["scan-lost", scan_name, "ejemplo.com", "", "", "", "RUNNING"]])
            self.assertEqual(parse_qs(request.content.decode()).get("id"), ["scan-lost"])
            return httpx.Response(200, json="")

        with with_transport(handler):
            with self.assertRaises(httpx.ReadTimeout):
                await orchestrators.run_spiderfoot("ejemplo.com", OrchestratorSettings())
        self.assertEqual(routes, ["/startscan", "/scanlist", "/stopscan"])


class TheHarvesterTests(unittest.IsolatedAsyncioTestCase):
    async def test_cuota_se_recuerda_entre_analisis_y_expira(self):
        calls = []

        async def collector(target, settings):
            calls.append(settings.theharvester_sources)
            limited = len(calls) == 1
            return RunnerOutput({
                "items": [{"type": "hostname", "value": "api.ejemplo.com", "sources": ["certspotter"]}],
                "runs": [{"target": target, "source_executions": [
                    {"source": "hackertarget", "status": "rate-limited", "stop_reason": "quota-exhausted"}
                ] if limited else [{"source": "certspotter", "status": "completed"}]}],
            }, error="cuota agotada" if limited else None)

        settings = OrchestratorSettings(crtsh_enabled=False)
        with (patch.dict(orchestrators._harvester_quota_until, {}, clear=True),
              patch.object(orchestrators.time, "monotonic", return_value=100) as clock,
              patch.object(orchestrators, "run_theharvester", side_effect=collector),
              patch.object(orchestrators, "run_spiderfoot", return_value=[])):
            first = (await run_all("ejemplo.com", settings))["theHarvester"]
            second = (await run_all("ejemplo.com", settings))["theHarvester"]
            clock.return_value += orchestrators._HARVESTER_QUOTA_COOLDOWN_SECONDS + 1
            third = (await run_all("ejemplo.com", settings))["theHarvester"]
        self.assertIn("hackertarget", calls[0])
        self.assertNotIn("hackertarget", calls[1])
        self.assertIn("hackertarget", calls[2])
        self.assertEqual(len(second["contenido"]["items"]), 1)
        self.assertIn("cuota agotada", second["error"])
        self.assertIn("cuota agotada", first["error"])
        self.assertIsNone(third["error"])
    async def test_agotamiento_omite_proveedor_solo_en_consultas_posteriores(self):
        calls = []
        warning = "theHarvester no completó la consulta de: hackertarget (rate-limited: quota-exhausted)"

        async def partial(target, settings):
            calls.append((target, settings.theharvester_sources))
            is_root = target == "ejemplo.com"
            return RunnerOutput({
                "hosts": ["api.ejemplo.com"], "ips": [], "emails": [], "asns": [],
                "items": [{"type": "hostname", "value": "api.ejemplo.com",
                           "sources": ["certspotter"], "targets": [target]}],
                "runs": [{"target": target, "source_executions": [
                    {"source": "hackertarget", "status": "rate-limited",
                     "stop_reason": "quota-exhausted", "result_count": 0},
                    {"source": "certspotter", "status": "completed", "result_count": 1},
                ] if is_root else [{"source": "certspotter", "status": "completed", "result_count": 1}]}],
            }, error=warning if is_root else None)

        with (patch.object(orchestrators, "run_theharvester", side_effect=partial),
              patch.object(orchestrators, "run_spiderfoot", return_value=[]),
              patch.object(orchestrators, "run_crtsh", return_value=[])):
            result = (await run_all(
                "ejemplo.com", OrchestratorSettings(),
                targets=["api.ejemplo.com", "dev.ejemplo.com", "www.ejemplo.com"],
            ))["theHarvester"]
        self.assertEqual([item[0] for item in calls], ["ejemplo.com", "api.ejemplo.com", "dev.ejemplo.com", "www.ejemplo.com"])
        self.assertIn("hackertarget", calls[0][1])
        self.assertTrue(all("hackertarget" not in sources for _, sources in calls[1:]))
        self.assertTrue(all("certspotter" in sources and "rapiddns" in sources and "urlscan" in sources for _, sources in calls))
        self.assertEqual(result["estado"], "completado")
        self.assertIn(warning, result["error"])
        self.assertEqual(len(result["contenido"]["items"]), 1)
        self.assertEqual(len(result["contenido"]["runs"]), 4)
        self.assertTrue(all(run["source_executions"][-1]["status"] == "skipped" for run in result["contenido"]["runs"][1:]))
        self.assertEqual(len(result["consultas"]), 4)
        self.assertTrue(all(query["metodo"] == "consulta de fuente" for query in result["consultas"]))

    async def test_reporte_marca_limite_de_proveedor_como_fallo(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            report.write_text(json.dumps({
                "type": "summary",
                "source_executions": [{"source": "certspotter", "status": "rate-limited"}],
            }), encoding="utf-8")
            warning = orchestrators._check_theharvester_source_status(report)
            self.assertIn("certspotter", warning)
            self.assertIn("rate-limited", warning)

    async def test_reporte_acepta_consulta_completa_sin_resultados(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            report.write_text(json.dumps({
                "type": "summary",
                "source_executions": [{"source": "certspotter", "status": "completed", "result_count": 0}],
            }), encoding="utf-8")
            orchestrators._check_theharvester_source_status(report)

    async def test_reporte_parcial_conserva_datos_y_reporta_fuente_fallida(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            report.write_text(json.dumps({
                "type": "summary",
                "source_executions": [
                    {"source": "certspotter", "status": "rate-limited"},
                    {"source": "hackertarget", "status": "completed", "result_count": 2},
                ],
            }), encoding="utf-8")
            warning = orchestrators._check_theharvester_source_status(report)
        self.assertIn("certspotter", warning)

        async def partial(_domain):
            return RunnerOutput(
                {"hosts": ["api.ejemplo.com"], "ips": [], "emails": [], "asns": []},
                error=warning,
            )

        result = (await run_all("ejemplo.com", OrchestratorSettings(), runners={"theHarvester": partial}))["theHarvester"]
        self.assertEqual(result["estado"], "completado")
        self.assertIn("api.ejemplo.com", result["contenido"]["hosts"])
        self.assertIn("certspotter", result["error"])

    async def test_jsonl_conserva_proveedor_y_hallazgos_aunque_otro_falle(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            report.write_text("\n".join(json.dumps(item) for item in [
                {"type": "summary", "target": "ejemplo.com", "source_executions": [
                    {"source": "certspotter", "status": "completed", "result_count": 1},
                    {"source": "hackertarget", "status": "rate-limited", "stop_reason": "quota-exhausted", "result_count": 0},
                ]},
                {"type": "hostname", "value": "api.ejemplo.com", "sources": ["certspotter"]},
                {"type": "url", "value": "https://docs.ejemplo.com/", "sources": ["certspotter"]},
            ]) + "\n", encoding="utf-8")
            parsed = orchestrators._read_theharvester_jsonl(report)
            self.assertEqual(parsed["hosts"], ["api.ejemplo.com"])
            self.assertEqual(parsed["items"][0]["sources"], ["certspotter"])
            self.assertEqual(parsed["items"][1]["type"], "url")
            self.assertEqual(parsed["runs"][0]["source_executions"][1]["stop_reason"], "quota-exhausted")

    async def test_jsonl_sin_proveedor_completo_conserva_resultado_parcial(self):
        class Process:
            returncode = 0

            async def communicate(self):
                return b"", b""

        async def spawn(*args, **kwargs):
            report = Path(args[args.index("-f") + 1]).with_suffix(".jsonl")
            report.write_text("\n".join(json.dumps(item) for item in [
                {"type": "summary", "target": "ejemplo.com", "source_executions": [
                    {"source": "certspotter", "status": "partial", "stop_reason": "runtime-limit", "result_count": 1},
                ]},
                {"type": "hostname", "value": "api.ejemplo.com", "sources": ["certspotter"]},
            ]) + "\n", encoding="utf-8")
            return Process()

        with (patch.object(orchestrators.shutil, "which", return_value="theHarvester"),
              patch.object(orchestrators.asyncio, "create_subprocess_exec", new=spawn)):
            output = await orchestrators.run_theharvester("ejemplo.com", OrchestratorSettings())
        self.assertIsInstance(output, RunnerOutput)
        self.assertFalse(output.failed)
        self.assertEqual(output.data["hosts"], ["api.ejemplo.com"])
        self.assertIn("runtime-limit", output.error)

    async def test_resultados_de_varios_objetivos_se_unifican_con_su_procedencia(self):
        first = {"hosts": ["api.ejemplo.com"], "items": [{
            "type": "hostname", "value": "api.ejemplo.com", "sources": ["certspotter"], "targets": ["ejemplo.com"],
        }], "runs": [{"target": "ejemplo.com"}]}
        second = {"hosts": ["api.ejemplo.com"], "items": [{
            "type": "hostname", "value": "API.ejemplo.com", "sources": ["urlscan"], "targets": ["api.ejemplo.com"],
        }], "runs": [{"target": "api.ejemplo.com"}]}
        merged = orchestrators._merge_source_data("theHarvester", [first, second])
        self.assertEqual(len(merged["items"]), 1)
        self.assertEqual(merged["items"][0]["sources"], ["certspotter", "urlscan"])
        self.assertEqual(merged["items"][0]["targets"], ["ejemplo.com", "api.ejemplo.com"])

    async def test_resumen_de_objetivo_fallido_permanece_en_reporte_parcial(self):
        failed = {"estado": "fallido", "contenido": {"items": [], "runs": [{"target": "api.ejemplo.com"}]}, "error": "cuota agotada"}
        completed = {"estado": "completado", "contenido": {"items": [{
            "type": "hostname", "value": "www.ejemplo.com", "sources": ["urlscan"],
        }], "runs": [{"target": "ejemplo.com"}]}, "error": None}
        merged = orchestrators._merge_outcomes("theHarvester", failed, completed)
        self.assertEqual(merged["estado"], "completado")
        self.assertEqual(len(merged["contenido"]["runs"]), 2)
        self.assertIn("cuota agotada", merged["error"])

    async def test_ruta_inexistente_no_expone_ruta_de_otro_equipo(self):
        unavailable = "/Users/another-machine/theHarvester"
        with patch.object(orchestrators.shutil, "which", return_value=None):
            outcome = (await run_all("ejemplo.com", OrchestratorSettings(), runners={"theHarvester": lambda d: orchestrators.run_theharvester(d, OrchestratorSettings(theharvester_bin=unavailable))}))["theHarvester"]
        self.assertIn("THEHARVESTER_BIN", outcome["error"])
        self.assertNotIn(unavailable, outcome["error"])

    async def test_cancelacion_termina_el_proceso_local(self):
        class Process:
            returncode = None
            killed = False

            def __init__(self):
                self.waiting = asyncio.Event()
                self.finished = asyncio.Event()

            async def communicate(self):
                self.waiting.set()
                await self.finished.wait()
                return b"", b""

            def kill(self):
                self.killed = True
                self.returncode = -9
                self.finished.set()

        process = Process()

        async def spawn(*args, **kwargs):
            return process

        with (
            patch.object(orchestrators.shutil, "which", return_value="theHarvester"),
            patch.object(orchestrators.asyncio, "create_subprocess_exec", new=spawn),
        ):
            job = asyncio.create_task(orchestrators.run_theharvester("ejemplo.com", OrchestratorSettings()))
            await asyncio.wait_for(process.waiting.wait(), timeout=2)
            job.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await job
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
