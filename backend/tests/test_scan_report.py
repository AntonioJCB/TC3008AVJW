import json
import unittest
from unittest.mock import MagicMock, patch
from app import main
from app.scan_report import build_coverage
from app.orchestrators import run_all, OrchestratorSettings

class CoverageTests(unittest.TestCase):
    @staticmethod
    def passive_report(provider, module, target, **extra):
        report = {
            "profile": "baxter-passive-v1", "provider": provider, "target": target,
            "status": "ok", "events": [], "checked_at": "2026-11-19T00:00:00Z", **extra,
        }
        return {
            "event_type": "RAW_RIR_DATA", "data": json.dumps(report), "module": module,
            "scan_target": target, "false_positive": 0,
        }

    def test_inventory_reads_beyond_execution_budget(self):
        rows = [{"tipo": "subdominio", "valor": f"s{i}.example.com"} for i in range(100)]
        with patch.object(main, "_execute", side_effect=[{"alcance": "example.com"}, rows, [{"tipo": "subdominio", "valor": "last.example.com"}]]):
            targets, _, _ = main._scan_targets(MagicMock(), {"organizacion_id": "o", "autorizacion_id": "a"}, "example.com", 2)
        self.assertEqual(len(targets), 102)
        self.assertIn("last.example.com", targets)

    def test_discovery_is_not_query_and_shared_ip_is_not_authorized(self):
        assets = [
            {"id": "a", "tipo": "subdominio", "valor": "api.example.com"},
            {"id": "ip", "tipo": "ip", "valor": "8.8.8.8"},
            {"id": "mail", "tipo": "correo", "valor": "contact@example.com"},
            {"id": "fixture", "tipo": "servicio", "valor": "203.0.113.10:22/tcp"},
        ]
        report = build_coverage(assets, {}, "example.com", ["example.com"])
        by_id = {row["id"]: row for row in report["activos"]}
        self.assertFalse(by_id["a"]["consultado"])
        self.assertIn("Sin registro", by_id["a"]["motivo"])
        self.assertEqual(by_id["ip"]["clasificacion_exposicion"], "fuera_alcance")
        self.assertEqual(by_id["mail"]["clasificacion_exposicion"], "sin_compatibilidad")
        self.assertEqual(by_id["fixture"]["clasificacion_exposicion"], "historico_sintetico")

    def test_only_completed_security_checks_mark_an_asset_as_evaluated(self):
        raw = [
            self.passive_report(
                "google_dns_doh", "sfp_baxter_dns_doh", "example.com",
                checks=[{"check": "spf", "state": "present"}],
            ),
            self.passive_report("urlscan", "sfp_baxter_urlscan", "info.example.com"),
        ]
        outcomes = {
            "crt.sh": {"estado": "completado", "contenido": [], "consultas": [
                {"objetivo": "info.example.com", "estado": "completado", "metodo": "CT", "error": None},
            ]},
            "SpiderFoot": {"estado": "completado", "contenido": raw, "consultas": [
                {"objetivo": "example.com", "estado": "completado", "metodo": "pasiva", "error": None},
                {"objetivo": "info.example.com", "estado": "completado", "metodo": "pasiva", "error": None},
            ]},
        }
        report = build_coverage([
            {"id": "dns", "tipo": "dominio", "valor": "example.com"},
            {"id": "info", "tipo": "subdominio", "valor": "info.example.com"},
        ], outcomes, "example.com", ["example.com", "info.example.com"])
        by_id = {row["id"]: row for row in report["activos"]}
        self.assertTrue(by_id["dns"]["evaluado_seguridad"])
        self.assertEqual(by_id["dns"]["comprobaciones_seguridad"][0]["proveedor"], "google_dns_doh")
        self.assertFalse(by_id["info"]["evaluado_seguridad"])

    def test_non_operational_assets_do_not_make_authorized_coverage_partial(self):
        report = build_coverage([
            {"id": "shared", "tipo": "ip", "valor": "8.8.8.8"},
            {"id": "mail", "tipo": "correo", "valor": "contact@example.com"},
            {"id": "fixture", "tipo": "servicio", "valor": "203.0.113.10:443/tcp"},
        ], {}, "example.com", ["example.com"])
        self.assertFalse(report["cobertura_incompleta"])

class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_budget_preserves_pending_targets_and_query_errors(self):
        called = []
        async def runner(target):
            called.append(target)
            if target.startswith("api"):
                raise RuntimeError("provider unavailable")
            return []
        result = await run_all("example.com", OrchestratorSettings(), runners={"SpiderFoot": runner}, targets=["api.example.com", "dev.example.com"], max_targets=2)
        self.assertEqual(called, ["example.com", "api.example.com"])
        self.assertEqual(result["SpiderFoot"]["objetivos_pendientes"], ["dev.example.com"])
        self.assertEqual(result["SpiderFoot"]["consultas"][1]["estado"], "fallido")

    async def test_excluded_synthetic_target_is_never_queried_and_keeps_reason(self):
        called = []
        async def runner(target):
            called.append(target)
            return []
        reason = "Objetivo sintético histórico derivado de DNS interno sin evidencia independiente"
        result = await run_all(
            "example.com", OrchestratorSettings(), runners={"SpiderFoot": runner},
            targets=["example.com", "www.example.com"], max_targets=20,
            excluded_targets={"dmarc.example.com": reason},
        )
        self.assertEqual(called, ["example.com", "www.example.com"])
        self.assertEqual(result["SpiderFoot"]["objetivos_pendientes"], ["dmarc.example.com"])
        self.assertEqual(result["SpiderFoot"]["objetivos_omitidos"]["dmarc.example.com"], reason)
        coverage = build_coverage(
            [{"id": "fake", "tipo": "subdominio", "valor": "dmarc.example.com"}],
            result, "example.com", ["example.com", "www.example.com"],
        )
        self.assertEqual(coverage["activos"][0]["motivo"], reason)

    async def test_discovered_target_is_queried_once(self):
        called = []
        async def runner(target):
            called.append(target)
            return [{"type": "INTERNET_NAME", "data": "api.example.com", "source": "example.com"}]
        result = await run_all("example.com", OrchestratorSettings(), runners={"SpiderFoot": runner}, max_targets=20)
        self.assertEqual(called, ["example.com", "api.example.com"])
        self.assertEqual(len(result["SpiderFoot"]["consultas"]), 2)
