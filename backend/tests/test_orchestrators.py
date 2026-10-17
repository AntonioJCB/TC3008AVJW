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
    def test_health_and_authentication_gate(self) -> None:
        client = TestClient(main.app)
        self.assertEqual(client.get("/health").json(), {"estado": "disponible"})
        response = client.post("/api/escaneos/00000000-0000-0000-0000-000000000001/ejecutar")
        self.assertEqual(response.status_code, 401)

    def test_authorization_scope_requires_exact_domain_for_apex_scan(self) -> None:
        self.assertTrue(main._scope_allows_domain("example.com, *.example.com", "example.com"))
        self.assertFalse(main._scope_allows_domain("*.example.com", "example.com"))

    def test_response_names_failed_source_and_marks_scan_incomplete(self) -> None:
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

        with (
            patch.object(main, "get_settings", return_value=settings),
            patch.object(main, "_supabase_client", return_value=object()),
            patch.object(main, "_verify_scope", return_value=({"organizacion_id": "org-id"}, "example.com")),
            patch.object(main, "_source_ids", return_value={name: name for name in main.SOURCE_NAMES}),
            patch.object(main, "_start_scan"),
            patch.object(main, "run_all", new=AsyncMock(return_value=outcomes)),
            patch.object(main, "_persist_source", side_effect=lambda *args: persisted[args[4]]),
            patch.object(main, "_finish_scan") as finish_scan,
        ):
            response = TestClient(main.app).post(f"/api/escaneos/{scan_id}/ejecutar")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["estado"], "incompleto")
        source_results = {source["fuente"]: source for source in response.json()["fuentes"]}
        self.assertEqual(source_results["Shodan"]["estado"], "fallido")
        self.assertIn("403", source_results["Shodan"]["error"])
        self.assertEqual(finish_scan.call_args.args[2], "incompleto")


if __name__ == "__main__":
    unittest.main()