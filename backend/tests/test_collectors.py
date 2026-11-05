import asyncio
import unittest
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
    async def test_reintenta_con_espera_creciente_y_termina_bien(self):
        respuestas = iter([httpx.Response(502), httpx.Response(504), httpx.Response(200, json=[{"id": 1}])])
        pausas = Pausas()
        with with_transport(lambda request: next(respuestas)), patch.object(orchestrators, "_sleep", pausas):
            datos = await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=3))
        self.assertEqual(datos, [{"id": 1}])
        self.assertEqual(pausas.valores, [2, 4])

    async def test_agota_los_reintentos_y_falla_sin_exponer_la_url(self):
        pausas = Pausas()
        with with_transport(lambda request: httpx.Response(503)), patch.object(orchestrators, "_sleep", pausas):
            with self.assertRaises(httpx.HTTPStatusError) as caught:
                await run_crtsh("ejemplo.com", OrchestratorSettings(crtsh_retries=3))
        self.assertEqual(len(pausas.valores), 2)
        self.assertIn("503", orchestrators._error_message(caught.exception))

    async def test_cuerpo_vacio_es_lista_vacia(self):
        with with_transport(lambda request: httpx.Response(200, text="")):
            self.assertEqual(await run_crtsh("ejemplo.com", OrchestratorSettings()), [])

    async def test_crtsh_usa_su_propio_tiempo_de_espera(self):
        limites = []

        def handler(request):
            limites.append(request.extensions["timeout"]["read"])
            return httpx.Response(200, json=[])

        with with_transport(handler):
            await run_crtsh("ejemplo.com", OrchestratorSettings(request_timeout_seconds=5, crtsh_timeout_seconds=60))
        self.assertEqual(limites, [60])

    async def test_un_error_4xx_no_se_reintenta(self):
        llamadas = []

        def handler(request):
            llamadas.append(1)
            return httpx.Response(400)

        with with_transport(handler), patch.object(orchestrators, "_sleep", Pausas()):
            with self.assertRaises(httpx.HTTPStatusError):
                await run_crtsh("ejemplo.com", OrchestratorSettings())
        self.assertEqual(len(llamadas), 1)


class ShodanTests(unittest.IsolatedAsyncioTestCase):
    def ajustes(self, **extra):
        return OrchestratorSettings(shodan_api_key="llave-secreta-123", **extra)

    async def test_sin_llave_falla_con_mensaje_claro(self):
        with self.assertRaisesRegex(RuntimeError, "SHODAN_API_KEY"):
            await run_shodan("ejemplo.com", OrchestratorSettings())

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


    async def test_inicia_grupo_pasivo_y_exporta_el_escaneo(self):
        rutas = []

        def handler(request):
            rutas.append(request.url.path)
            if request.url.path == "/startscan":
                form = parse_qs(request.content.decode())
                # SpiderFoot v4 guarda los nombres de grupo con esta capitalización.
                if form.get("usecase") != ["Passive"]:
                    return httpx.Response(200, json=["ERROR", "Incorrect usage: no modules specified for scan."])
                return httpx.Response(200, json=["SUCCESS", "scan-123"])
            self.assertEqual(request.url.params.get("id") or request.url.params.get("ids"), "scan-123")
            if request.url.path == "/scanstatus":
                return httpx.Response(200, json=[None, None, None, None, None, "FINISHED"])
            return httpx.Response(200, json=[{"data": "ejemplo.com"}])

        with with_transport(handler):
            datos = await orchestrators.run_spiderfoot("ejemplo.com", OrchestratorSettings())
        self.assertEqual(datos, [{"data": "ejemplo.com"}])
        self.assertEqual(rutas, ["/startscan", "/scanstatus", "/scanexportjsonmulti"])

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


class TheHarvesterTests(unittest.IsolatedAsyncioTestCase):
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
