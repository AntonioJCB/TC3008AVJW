import asyncio
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from httpx import ReadError

from app import scan_service
from app.scan_service import SOURCE_NAMES, _execute, calculate_risk_with_retry, compute_scan_state, run_scan_job, scan_message

OK = {"estado": "completado"}
KO = {"estado": "fallido", "error": "Proveedor no disponible"}


def resultados(**estados):
    return {n: estados.get(n.replace(".", "").lower(), OK) for n in SOURCE_NAMES}


class EstadoDelEscaneoTests(unittest.TestCase):
    def test_crtsh_deshabilitado_no_impide_completar_fuentes_habilitadas(self):
        rows = {"crt.sh": {"estado": "deshabilitado", "error": "Fuente deshabilitada temporalmente: CT"},
                "theHarvester": OK, "SpiderFoot": OK}
        self.assertEqual(compute_scan_state(rows), "completado")
        message = scan_message("completado", rows)
        self.assertIn("2 fuentes habilitadas", message)
        self.assertIn("Deshabilitadas/no evaluadas: crt.sh", message)

    def test_todas_bien_es_completado(self):
        self.assertEqual(compute_scan_state({n: OK for n in SOURCE_NAMES}), "completado")

    def test_una_falla_es_incompleto(self):
        self.assertEqual(compute_scan_state({**{n: OK for n in SOURCE_NAMES}, "theHarvester": KO}), "incompleto")

    def test_shodan_desactivado_no_altera_el_estado(self):
        self.assertNotIn("Shodan", SOURCE_NAMES)
        self.assertNotIn("Web", SOURCE_NAMES)
        self.assertEqual(compute_scan_state({**{n: OK for n in SOURCE_NAMES}, "Shodan": KO}), "completado")

    def test_tres_fallan_sigue_siendo_incompleto(self):
        r = {n: KO for n in SOURCE_NAMES}
        r["crt.sh"] = OK
        self.assertEqual(compute_scan_state(r), "incompleto")

    def test_todas_fallan_es_fallido(self):
        self.assertEqual(compute_scan_state({n: KO for n in SOURCE_NAMES}), "fallido")

    def test_una_fuente_ausente_cuenta_como_fallida(self):
        self.assertEqual(compute_scan_state({"crt.sh": OK}), "incompleto")
        self.assertEqual(compute_scan_state({}), "fallido")

    def test_theharvester_fallido_con_jsonl_conserva_respuesta_cruda(self):
        client = MagicMock()
        outcome = {"estado": "fallido", "contenido": {"items": [], "runs": [{"target": "ejemplo.com"}]}, "error": "cuota agotada"}
        summary = {"resultado_crudo_id": "raw-id", "ya_procesado": False, "observaciones_generadas": 0,
                   "activos_nuevos": 0, "activos_existentes": 0, "observaciones_nuevas": 0,
                   "observaciones_duplicadas": 0, "descartadas": {}}
        with (patch.object(scan_service, "ingestar_resultado", return_value=summary) as ingest,
              patch.object(scan_service, "_execute", return_value=[])):
            stored = scan_service._persist_source(client, "org", "scan", "source", "theHarvester", "ejemplo.com", outcome)
        ingest.assert_called_once()
        self.assertEqual(stored["resultado_crudo_id"], "raw-id")
        self.assertEqual(stored["estado"], "fallido")


class MensajesTests(unittest.TestCase):
    def test_incompleto_dice_cual_fallo_y_cuales_no(self):
        r = {**{n: OK for n in SOURCE_NAMES}, "theHarvester": KO}
        mensaje = scan_message("incompleto", r)
        self.assertIn("Fallaron: theHarvester (Proveedor no disponible)", mensaje)
        self.assertIn("Terminaron correctamente: crt.sh, SpiderFoot", mensaje)

    def test_completado_en_curso_y_pendiente(self):
        self.assertIn(f"{len(SOURCE_NAMES)} fuentes habilitadas terminaron correctamente", scan_message("completado", {n: OK for n in SOURCE_NAMES}))
        self.assertIn(f"2 de {len(SOURCE_NAMES)}", scan_message("ejecutando", {"crt.sh": OK, "theHarvester": KO, "SpiderFoot": {"estado": "ejecutando"}}))
        self.assertIn("pendiente", scan_message("pendiente", {}))

    def test_un_error_largo_se_recorta(self):
        r = {n: KO for n in SOURCE_NAMES}
        r["theHarvester"] = {"estado": "fallido", "error": "x" * 900}
        self.assertLess(len(scan_message("fallido", r)), 900)


class ExecuteTests(unittest.TestCase):
    class Consulta:
        def __init__(self, respuesta, falla=False):
            self.respuesta, self.falla = respuesta, falla

        def execute(self):
            if self.falla:
                raise RuntimeError("caída")
            return self.respuesta

    def test_maybe_single_sin_filas_devuelve_none_en_lugar_de_romper(self):
        self.assertIsNone(_execute(self.Consulta(None)))

    def test_devuelve_los_datos(self):
        self.assertEqual(_execute(self.Consulta(SimpleNamespace(data=[{"id": 1}]))), [{"id": 1}])

    def test_un_error_de_red_es_502(self):
        with self.assertRaises(HTTPException) as caught, self.assertLogs(scan_service.logger, logging.ERROR):
            _execute(self.Consulta(None, falla=True))
        self.assertEqual(caught.exception.status_code, 502)


class RunScanJobTests(unittest.IsolatedAsyncioTestCase):
    SETTINGS = SimpleNamespace(
        shodan_api_key=None, theharvester_bin="x", theharvester_sources="x", spiderfoot_url="http://x",
        spiderfoot_modules="sfp_dnsresolve,sfp_dnsraw,sfp_robtex,sfp_crobat_api",
        request_timeout_seconds=1, process_timeout_seconds=1, spiderfoot_timeout_seconds=1, spiderfoot_poll_seconds=1,
        scan_timeout_seconds=5, crtsh_retries=1, crtsh_timeout_seconds=60, shodan_max_ips=1, shodan_pause_seconds=0,
    )
    SCAN = {"id": "scan-1", "organizacion_id": "org-1"}
    IDS = {n: f"id-{n}" for n in SOURCE_NAMES}

    def test_crtsh_fallido_guarda_reporte_sin_generar_observaciones(self):
        summary = {
            "resultado_crudo_id": "raw-crt", "ya_procesado": False,
            "observaciones_generadas": 0, "activos_nuevos": 0, "activos_existentes": 0,
            "observaciones_nuevas": 0, "observaciones_duplicadas": 0, "descartadas": {},
        }
        outcome = {"estado": "fallido", "error": "HTTP 502", "contenido": {
            "version": 1, "entries": [], "queries": [{"query": "%.example.com", "status": "error"}],
            "covered_targets": ["example.com"],
        }}
        with (patch.object(scan_service, "ingestar_resultado", return_value=summary) as ingest,
              patch.object(scan_service, "_execute")):
            saved = scan_service._persist_source(
                MagicMock(), "org", "scan", "source", "crt.sh", "example.com", outcome,
            )
        ingest.assert_called_once()
        self.assertEqual(saved["estado"], "fallido")
        self.assertEqual(saved["resultado_crudo_id"], "raw-crt")
        self.assertEqual(saved["observaciones_generadas"], 0)

    def test_ampliacion_conserva_contadores_sin_duplicar_observaciones(self):
        previous = {
            "estado": "completado", "resultado_crudo_id": "raw-first", "ya_procesado": False,
            "observaciones_generadas": 2, "activos_nuevos": 1, "activos_existentes": 1,
            "observaciones_nuevas": 2, "observaciones_duplicadas": 0, "descartadas": {},
        }
        cumulative = {
            "resultado_crudo_id": "raw-final", "ya_procesado": False,
            "observaciones_generadas": 4, "activos_nuevos": 1, "activos_existentes": 3,
            "observaciones_nuevas": 1, "observaciones_duplicadas": 3, "descartadas": {},
        }
        with (
            patch.object(scan_service, "ingestar_resultado", return_value=cumulative),
            patch.object(scan_service, "_execute"),
        ):
            saved = scan_service._persist_source(
                MagicMock(), "org", "scan", "source", "SpiderFoot", "example.com",
                {"estado": "completado", "contenido": [], "error": None}, previous,
            )
        self.assertEqual(saved["observaciones_generadas"], 4)
        self.assertEqual(saved["observaciones_nuevas"], 3)
        self.assertEqual(saved["observaciones_duplicadas"], 1)
        self.assertEqual(saved["activos_nuevos"], 2)
        self.assertEqual(saved["activos_existentes"], 2)

    async def test_riesgo_se_reintenta_si_supabase_corta_la_conexion(self):
        with (
            patch.object(scan_service, "calcular_y_guardar", side_effect=[ReadError("red"), None]) as risk,
            patch.object(scan_service.asyncio, "sleep") as sleep,
        ):
            await calculate_risk_with_retry(object(), "scan-1")
        self.assertEqual(risk.call_count, 2)
        sleep.assert_awaited_once_with(1.0)

    async def test_error_del_motor_no_se_reintenta_como_error_de_red(self):
        with patch.object(scan_service, "calcular_y_guardar", side_effect=ValueError("regla inválida")) as risk:
            with self.assertRaises(ValueError):
                await calculate_risk_with_retry(object(), "scan-1")
        risk.assert_called_once()

    async def correr(self, estados, riesgo_falla=False, persistencia_falla=()):
        async def runner_ok(domain):
            return []

        async def runner_ko(domain):
            raise RuntimeError("proveedor caído")

        runners = {n: (runner_ok if estados[n] == "ok" else runner_ko) for n in SOURCE_NAMES}

        def persist(client, org, scan, source_id, name, domain, outcome, previous=None, nvd_api_key=None):
            if name in persistencia_falla:
                raise RuntimeError("base de datos caída")
            return {"estado": outcome["estado"], "error": outcome["error"]}

        with (
            patch.object(scan_service, "_persist_source", side_effect=persist) as p,
            patch.object(scan_service, "_finish_scan") as finish,
            patch.object(scan_service, "audit") as auditoria,
            patch.object(scan_service, "calcular_y_guardar", side_effect=RuntimeError("motor") if riesgo_falla else None) as riesgo,
            self.assertLogs(scan_service.logger, logging.INFO) as registros,
        ):
            estado = await run_scan_job(object(), self.SETTINGS, self.SCAN, self.IDS, "ejemplo.com", runners)
        self.registros = registros.output
        self.auditoria = auditoria
        return estado, p, finish, riesgo

    async def test_todas_bien(self):
        estado, persist, finish, riesgo = await self.correr({n: "ok" for n in SOURCE_NAMES})
        self.assertEqual(estado, "completado")
        self.assertEqual(finish.call_args.args[2], "completado")
        riesgo.assert_called_once()

    async def test_flujo_completo_sin_crtsh_conserva_theharvester_y_completa(self):
        settings = SimpleNamespace(**{**vars(self.SETTINGS), "crtsh_enabled": False})
        outcomes = {
            "theHarvester": {"estado": "completado", "error": None, "contenido": {"items": [1, 2, 3]}, "consultas": []},
            "SpiderFoot": {"estado": "completado", "error": None, "contenido": [], "consultas": []},
        }

        async def collect(_domain, _settings, *, on_result, **_options):
            for name, outcome in outcomes.items():
                await on_result(name, outcome)
            return outcomes

        def persist(_client, _org, _scan, _source_id, name, _domain, outcome, previous=None, nvd_api_key=None):
            return {"estado": outcome["estado"], "error": outcome["error"],
                    "observaciones_generadas": 3 if name == "theHarvester" else 76}

        with (
            patch.object(scan_service, "run_all", side_effect=collect),
            patch.object(scan_service, "_persist_source", side_effect=persist),
            patch.object(scan_service, "_persist_disabled_source", return_value={
                "estado": "deshabilitado", "error": "Fuente deshabilitada temporalmente: CT",
            }),
            patch.object(scan_service, "inventory", return_value=[]),
            patch.object(scan_service, "build_coverage", return_value={"objetivos_pendientes": []}),
            patch.object(scan_service, "_finish_scan", return_value=True),
            patch.object(scan_service, "audit"),
            patch.object(scan_service, "calcular_y_guardar"),
        ):
            state = await run_scan_job(object(), settings, self.SCAN, self.IDS, "ejemplo.com")
        self.assertEqual(state, "completado")


    async def test_una_falla_las_otras_se_guardan_y_queda_incompleto(self):
        estado, persist, finish, riesgo = await self.correr({**{n: "ok" for n in SOURCE_NAMES}, "theHarvester": "ko"})
        self.assertEqual(estado, "incompleto")
        self.assertEqual(persist.call_count, len(SOURCE_NAMES))  # también se registra la que falló
        self.assertEqual(finish.call_args.args[2], "incompleto")
        detalle = self.auditoria.call_args.kwargs["detail"]
        self.assertEqual(self.auditoria.call_args.kwargs["action"], "escaneo_finalizado")
        self.assertEqual(list(detalle["fuentes_fallidas"]), ["theHarvester"])
        self.assertEqual(detalle["fuentes_ok"], ["crt.sh", "SpiderFoot"])

    async def test_todas_fallan_es_fallido_pero_igual_se_calcula_el_riesgo_parcial(self):
        estado, _, finish, riesgo = await self.correr({n: "ko" for n in SOURCE_NAMES})
        self.assertEqual(estado, "fallido")
        riesgo.assert_called_once()

    async def test_si_falla_al_guardar_una_fuente_se_marca_fallida_y_el_escaneo_cierra(self):
        estado, _, finish, _ = await self.correr({n: "ok" for n in SOURCE_NAMES}, persistencia_falla=("crt.sh",))
        self.assertTrue(any("ERROR" in linea and "crt.sh" in linea for linea in self.registros))
        self.assertEqual(estado, "incompleto")
        self.assertEqual(finish.call_args.args[2], "incompleto")

    async def test_si_falla_el_calculo_de_riesgo_el_escaneo_queda_cerrado_igual(self):
        estado, _, finish, _ = await self.correr({n: "ok" for n in SOURCE_NAMES}, riesgo_falla=True)
        self.assertTrue(any("ERROR" in linea and "riesgo" in linea for linea in self.registros))
        self.assertEqual(estado, "completado")
        finish.assert_called_once()

    async def test_detener_cancela_las_fuentes_activas_y_conserva_la_terminada(self):
        scan = {**self.SCAN, "solicitado_por": "user-1"}
        saved = asyncio.Event()
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()

        async def quick(_domain):
            return [{"source": "crt.sh"}]

        async def slow(_domain):
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                stopped.set()
                raise

        def persist(_client, _org, _scan, _source_id, name, _domain, outcome, previous=None, nvd_api_key=None):
            if name == "crt.sh":
                loop.call_soon_threadsafe(saved.set)
            return {"estado": outcome["estado"], "error": outcome["error"]}

        scan_service.register_scan_control(scan["id"])
        with (
            patch.object(scan_service, "_persist_source", side_effect=persist) as persisted,
            patch.object(scan_service, "_cancel_scan", return_value=True),
            patch.object(scan_service, "_finish_scan") as finished,
            patch.object(scan_service, "calcular_y_guardar") as risk,
        ):
            job = asyncio.create_task(run_scan_job(
                object(), self.SETTINGS, scan, self.IDS, "ejemplo.com",
                {name: quick if name == "crt.sh" else slow for name in SOURCE_NAMES},
            ))
            await asyncio.wait_for(saved.wait(), timeout=2)
            self.assertTrue(await scan_service.cancel_scan(object(), scan["id"]))
            self.assertEqual(await asyncio.wait_for(job, timeout=2), "cancelado")

        self.assertTrue(stopped.is_set())
        self.assertEqual(persisted.call_count, 1)
        finished.assert_not_called()
        risk.assert_not_called()

    def test_mensaje_de_escaneo_detenido(self):
        self.assertIn("detenido", scan_message("cancelado", {"crt.sh": OK}).lower())


if __name__ == "__main__":
    unittest.main()


class AuditoriaTests(unittest.TestCase):
    def test_un_fallo_al_auditar_nunca_interrumpe(self):
        class Cliente:
            def table(self, nombre):
                raise RuntimeError("bitácora caída")

        with self.assertLogs(scan_service.logger, logging.WARNING):
            scan_service.audit(Cliente(), user_id="u", organization_id="o", action="x", scan_id="s")
