import logging
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app import scan_service
from app.scan_service import SOURCE_NAMES, _execute, compute_scan_state, run_scan_job, scan_message

OK = {"estado": "completado"}
KO = {"estado": "fallido", "error": "HTTP 403 from api.shodan.io"}


def resultados(**estados):
    return {n: estados.get(n.replace(".", "").lower(), OK) for n in SOURCE_NAMES}


class EstadoDelEscaneoTests(unittest.TestCase):
    def test_todas_bien_es_completado(self):
        self.assertEqual(compute_scan_state({n: OK for n in SOURCE_NAMES}), "completado")

    def test_una_falla_es_incompleto(self):
        self.assertEqual(compute_scan_state({**{n: OK for n in SOURCE_NAMES}, "Shodan": KO}), "incompleto")

    def test_tres_fallan_sigue_siendo_incompleto(self):
        r = {n: KO for n in SOURCE_NAMES}
        r["crt.sh"] = OK
        self.assertEqual(compute_scan_state(r), "incompleto")

    def test_todas_fallan_es_fallido(self):
        self.assertEqual(compute_scan_state({n: KO for n in SOURCE_NAMES}), "fallido")

    def test_una_fuente_ausente_cuenta_como_fallida(self):
        self.assertEqual(compute_scan_state({"crt.sh": OK}), "incompleto")
        self.assertEqual(compute_scan_state({}), "fallido")


class MensajesTests(unittest.TestCase):
    def test_incompleto_dice_cual_fallo_y_cuales_no(self):
        r = {**{n: OK for n in SOURCE_NAMES}, "Shodan": KO}
        mensaje = scan_message("incompleto", r)
        self.assertIn("Fallaron: Shodan (HTTP 403 from api.shodan.io)", mensaje)
        self.assertIn("Terminaron correctamente: crt.sh, theHarvester, SpiderFoot", mensaje)

    def test_completado_en_curso_y_pendiente(self):
        self.assertIn("4 fuentes terminaron correctamente", scan_message("completado", {n: OK for n in SOURCE_NAMES}))
        self.assertIn("2 de 4", scan_message("ejecutando", {"crt.sh": OK, "Shodan": KO, "SpiderFoot": {"estado": "ejecutando"}}))
        self.assertIn("pendiente", scan_message("pendiente", {}))

    def test_un_error_largo_se_recorta(self):
        r = {n: KO for n in SOURCE_NAMES}
        r["Shodan"] = {"estado": "fallido", "error": "x" * 900}
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
        request_timeout_seconds=1, process_timeout_seconds=1, spiderfoot_timeout_seconds=1, spiderfoot_poll_seconds=1,
        scan_timeout_seconds=5, crtsh_retries=1, shodan_max_ips=1, shodan_pause_seconds=0,
    )
    SCAN = {"id": "scan-1", "organizacion_id": "org-1"}
    IDS = {n: f"id-{n}" for n in SOURCE_NAMES}

    async def correr(self, estados, riesgo_falla=False, persistencia_falla=()):
        async def runner_ok(domain):
            return []

        async def runner_ko(domain):
            raise RuntimeError("proveedor caído")

        runners = {n: (runner_ok if estados[n] == "ok" else runner_ko) for n in SOURCE_NAMES}

        def persist(client, org, scan, source_id, name, domain, outcome):
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

    async def test_una_falla_las_otras_se_guardan_y_queda_incompleto(self):
        estado, persist, finish, riesgo = await self.correr({**{n: "ok" for n in SOURCE_NAMES}, "Shodan": "ko"})
        self.assertEqual(estado, "incompleto")
        self.assertEqual(persist.call_count, 4)  # también se registra la que falló
        self.assertEqual(finish.call_args.args[2], "incompleto")
        detalle = self.auditoria.call_args.kwargs["detail"]
        self.assertEqual(self.auditoria.call_args.kwargs["action"], "escaneo_finalizado")
        self.assertEqual(list(detalle["fuentes_fallidas"]), ["Shodan"])
        self.assertEqual(detalle["fuentes_ok"], ["crt.sh", "theHarvester", "SpiderFoot"])

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


if __name__ == "__main__":
    unittest.main()


class AuditoriaTests(unittest.TestCase):
    def test_un_fallo_al_auditar_nunca_interrumpe(self):
        class Cliente:
            def table(self, nombre):
                raise RuntimeError("bitácora caída")

        with self.assertLogs(scan_service.logger, logging.WARNING):
            scan_service.audit(Cliente(), user_id="u", organization_id="o", action="x", scan_id="s")
