import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from app import main
from app.orchestrators import OrchestratorSettings, run_all


class RunAllTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_failure_does_not_cancel_other_sources(self) -> None:
        async def succeeds(domain: str) -> dict[str, str]:
            return {"domain": domain}

        async def fails(domain: str) -> None:
            raise RuntimeError("provider unavailable")

        outcomes = await run_all(
            "example.com",
            OrchestratorSettings(),
            runners={
                "crt.sh": succeeds,
                "Shodan": fails,
                "theHarvester": succeeds,
                "SpiderFoot": succeeds,
            },
        )

        self.assertEqual(set(outcomes), {"crt.sh", "Shodan", "theHarvester", "SpiderFoot"})
        self.assertEqual(outcomes["Shodan"]["estado"], "fallido")
        self.assertIn("provider unavailable", outcomes["Shodan"]["error"])
        for source in ("crt.sh", "theHarvester", "SpiderFoot"):
            self.assertEqual(outcomes[source]["estado"], "completado")
            self.assertEqual(outcomes[source]["contenido"], {"domain": "example.com"})

    async def test_provider_error_does_not_expose_query_credentials(self) -> None:
        async def fails(domain: str) -> None:
            request = httpx.Request(
                "GET", "https://api.shodan.io/shodan/host/search?key=private-key"
            )
            response = httpx.Response(403, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)

        outcomes = await run_all(
            "example.com",
            OrchestratorSettings(),
            runners={"Shodan": fails},
        )

        self.assertEqual(outcomes["Shodan"]["estado"], "fallido")
        self.assertIn("403", outcomes["Shodan"]["error"])
        self.assertNotIn("private-key", outcomes["Shodan"]["error"])


class ScanEndpointTests(unittest.TestCase):
    def test_token_invalido_no_intenta_conectar_a_supabase(self):
        with patch.object(main, "_supabase_client") as client:
            response = TestClient(main.app).get("/api/escaneos", headers={"Authorization": "Bearer 1"})
        self.assertEqual(response.status_code, 401)
        client.assert_not_called()

    def test_health_and_authentication_gate(self) -> None:
        client = TestClient(main.app)
        self.assertEqual(client.get("/health").json(), {"estado": "disponible"})
        response = client.post("/api/escaneos/00000000-0000-0000-0000-000000000001/ejecutar")
        self.assertEqual(response.status_code, 401)

    def test_authorization_scope_requires_exact_domain_for_apex_scan(self) -> None:
        self.assertTrue(main._scope_allows_domain("example.com, *.example.com", "example.com"))
        self.assertFalse(main._scope_allows_domain("*.example.com", "example.com"))

    def test_execute_responds_202_and_marks_scan_incomplete_when_one_source_fails(self) -> None:
        """El escaneo corre en segundo plano: la respuesta es inmediata y el resultado queda guardado."""
        scan_id = "00000000-0000-0000-0000-000000000001"
        main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-id")
        self.addCleanup(main.app.dependency_overrides.clear)

        settings = SimpleNamespace(
            shodan_api_key="test-key",
            theharvester_bin="theHarvester",
            theharvester_sources="crtsh,certspotter",
            spiderfoot_url="http://127.0.0.1:5001",
            request_timeout_seconds=30,
            process_timeout_seconds=900,
            spiderfoot_timeout_seconds=1800,
            spiderfoot_poll_seconds=3,
            scan_timeout_seconds=2100,
            crtsh_retries=3,
            shodan_max_ips=10,
            shodan_pause_seconds=1.1,
        )
        outcomes = {
            name: {
                "estado": "fallido" if name == "Shodan" else "completado",
                "contenido": None if name == "Shodan" else [],
                "error": "HTTP 403 from api.shodan.io" if name == "Shodan" else None,
            }
            for name in main.SOURCE_NAMES
        }
        persisted = {
            name: {
                "estado": outcome["estado"],
                "error": outcome["error"],
                "resultado_crudo_id": None,
                "finalizado_en": "2026-10-16T00:00:00+00:00",
            }
            for name, outcome in outcomes.items()
        }

        async def fake_run_all(domain, orchestrator_settings, runners=None, on_result=None, timeout_seconds=None):
            for name, outcome in outcomes.items():
                await on_result(name, outcome)
            return outcomes

        with (
            patch.object(main, "get_settings", return_value=settings),
            patch.object(main, "_supabase_client", return_value=object()),
            patch.object(main, "_verify_scope", return_value=({"id": scan_id, "organizacion_id": "org-id"}, "example.com")),
            patch.object(main, "_source_ids", return_value={name: name for name in main.SOURCE_NAMES}),
            patch.object(main, "_start_scan"),
            patch("app.scan_service.run_all", new=fake_run_all),
            patch("app.scan_service._persist_source", side_effect=lambda *args: persisted[args[4]]) as persist,
            patch("app.scan_service._finish_scan") as finish_scan,
            patch("app.scan_service.audit"),
            patch("app.scan_service.calcular_y_guardar") as risk,
        ):
            response = TestClient(main.app).post(f"/api/escaneos/{scan_id}/ejecutar")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["estado"], "ejecutando")
        self.assertEqual(persist.call_count, 4)
        self.assertEqual(finish_scan.call_args.args[2], "incompleto")
        risk.assert_called_once()


if __name__ == "__main__":
    unittest.main()
