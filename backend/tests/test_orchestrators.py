import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from app import main
from app.orchestrators import OrchestratorSettings, RunnerOutput, run_all
from app.osint_normalization import adaptar
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo


class RunAllTests(unittest.IsolatedAsyncioTestCase):
    async def test_crtsh_fallido_conserva_detalle_sin_contar_como_cobertura(self) -> None:
        async def crtsh(_target: str):
            return RunnerOutput({
                "version": 1, "entries": [], "covered_targets": ["example.com"],
                "queries": [{"query": "%.example.com", "status": "error", "entries": 0, "error": "HTTP 502"}],
            }, error="HTTP 502", failed=True)

        result = await run_all("example.com", OrchestratorSettings(), runners={"crt.sh": crtsh})
        self.assertEqual(result["crt.sh"]["estado"], "fallido")
        self.assertEqual(result["crt.sh"]["contenido"]["queries"][0]["status"], "error")

    async def test_crtsh_wildcard_cubre_inventario_y_descubrimientos_sin_consultas_redundantes(self) -> None:
        consulted: list[str] = []
        saved: list[dict] = []

        async def crtsh(target: str):
            consulted.append(target)
            return RunnerOutput({
                "version": 1,
                "entries": [{"name_value": "api.example.com\ndev.example.com"}],
                "queries": [{"query": "%.example.com", "status": "ok", "entries": 1}],
                "covered_targets": [target],
            })

        async def spiderfoot(_target: str):
            return []

        async def on_result(name: str, outcome: dict):
            if name == "crt.sh":
                saved.append(outcome)

        outcomes = await run_all(
            "example.com", OrchestratorSettings(),
            runners={"crt.sh": crtsh, "SpiderFoot": spiderfoot},
            targets=["example.com", "api.example.com"], max_targets=3,
            on_result=on_result,
        )
        self.assertEqual(consulted, ["example.com"])
        self.assertEqual(set(outcomes["crt.sh"]["contenido"]["covered_targets"]),
                         {"example.com", "api.example.com", "dev.example.com"})
        self.assertEqual(len(saved), 2)
        self.assertEqual(len(adaptar("crt.sh", outcomes["crt.sh"]["contenido"], "example.com")["observaciones"]), 4)

    async def test_flujo_multiactivo_conserva_cve_potencial_sin_puntuar(self) -> None:
        consulted: list[tuple[str, str]] = []

        async def crtsh(target: str):
            consulted.append(("crt.sh", target))
            return [{"name_value": "api.example.com\nshop.example.com"}] if target == "example.com" else []

        async def spiderfoot(target: str):
            consulted.append(("SpiderFoot", target))
            if target in {"api.example.com", "shop.example.com"}:
                return [{"type": "VULNERABILITY_CVE_HIGH", "data": "CVE-2024-12345", "source": target}]
            return []

        async def harvester(_target: str):
            raise RuntimeError("proveedor no disponible")

        outcomes = await run_all(
            "example.com", OrchestratorSettings(),
            runners={"crt.sh": crtsh, "SpiderFoot": spiderfoot, "theHarvester": harvester},
            targets=["example.com"], max_targets=3,
        )
        self.assertEqual({target for source, target in consulted if source == "SpiderFoot"},
                         {"example.com", "api.example.com", "shop.example.com"})
        items = adaptar("SpiderFoot", outcomes["SpiderFoot"]["contenido"], "example.com")["observaciones"]
        observations = [
            Obs(str(i), f"asset-{item['valor']}", item["tipo"], item["valor"], item["atributo"],
                item["datos"], "SpiderFoot", "spiderfoot-id")
            for i, item in enumerate(items)
        ]
        rule = Regla("cve-rule", "INFRA-003", "CVE", "infraestructura", "media", 8)
        risk = evaluar_riesgo(observations, [rule],
                              {"SpiderFoot": "completado", "theHarvester": "fallido"})
        self.assertEqual(risk.hallazgos, [])
        self.assertEqual(risk.puntaje.puntaje_global, 0)
        self.assertTrue(risk.puntaje.es_parcial)

    async def test_ip_descubierta_solo_se_consulta_con_autorizacion_explicita(self) -> None:
        consulted: list[str] = []

        async def spiderfoot(target: str):
            if target == "example.com":
                return [
                    {"type": "IP_ADDRESS", "data": "8.8.8.8"},
                    {"type": "IP_ADDRESS", "data": "1.1.1.1"},
                ]
            return []

        async def ip_source(target: str):
            consulted.append(target)
            return []

        await run_all(
            "example.com", OrchestratorSettings(),
            runners={"SpiderFoot": spiderfoot, "FuenteIP": ip_source},
            targets=["example.com"], max_targets=3, ip_scope="example.com, 8.8.8.8",
        )
        self.assertIn("8.8.8.8", consulted)
        self.assertNotIn("1.1.1.1", consulted)

    async def test_subdominio_descubierto_se_analiza_y_puede_generar_hallazgo(self) -> None:
        consulted: list[tuple[str, str]] = []
        saved: list[str] = []

        async def on_result(name: str, _outcome: dict):
            saved.append(name)

        async def crtsh(target: str):
            consulted.append(("crt.sh", target))
            return [{"name_value": "api.example.com\notro.net"}]

        async def spiderfoot(target: str):
            consulted.append(("SpiderFoot", target))
            if target == "api.example.com":
                return [{"type": "EMAILADDR", "data": "alerts@api.example.com"}]
            return []

        outcomes = await run_all(
            "example.com", OrchestratorSettings(),
            runners={"crt.sh": crtsh, "SpiderFoot": spiderfoot},
            targets=["example.com"], max_targets=3, on_result=on_result,
        )
        self.assertEqual(consulted.count(("SpiderFoot", "api.example.com")), 1)
        self.assertNotIn(("SpiderFoot", "otro.net"), consulted)
        self.assertIn(("crt.sh", "api.example.com"), consulted)
        self.assertEqual(saved.count("crt.sh"), 2)
        self.assertEqual(saved.count("SpiderFoot"), 2)
        items = adaptar("SpiderFoot", outcomes["SpiderFoot"]["contenido"], "example.com")["observaciones"]
        observations = [
            Obs(str(index), "asset-mail", item["tipo"], item["valor"], item["atributo"],
                item.get("datos", {}), "SpiderFoot", "source-spiderfoot")
            for index, item in enumerate(items)
        ]
        rule = Regla("rule-mail", "IDEN-003", "Correo público", "identidad_digital", "baja", 5)
        result = evaluar_riesgo(observations, [rule], {"SpiderFoot": "completado", "theHarvester": "fallido"})
        self.assertEqual(len(result.hallazgos), 1)
        self.assertEqual(result.hallazgos[0].activo_id, "asset-mail")
        self.assertGreater(result.puntaje.puntaje_global, 0)
        self.assertTrue(result.puntaje.es_parcial)

    async def test_consulta_hosts_autorizados_y_conserva_resultados_parciales(self) -> None:
        consulted: list[tuple[str, str]] = []

        async def crtsh(target: str):
            consulted.append(("crt.sh", target))
            return [{"name_value": target}]

        async def ip_source(target: str):
            consulted.append(("FuenteIP", target))
            if target.startswith("api."):
                raise RuntimeError("límite del proveedor")
            return RunnerOutput([{"ip_str": "198.51.100.7"}], ("198.51.100.7",))

        async def harvester(target: str):
            consulted.append(("theHarvester", target))
            return {"hosts": [target], "ips": [], "emails": [], "asns": []}

        async def spiderfoot(target: str):
            consulted.append(("SpiderFoot", target))
            return [{"type": "INTERNET_NAME", "data": target}]

        results = await run_all(
            "example.com", OrchestratorSettings(),
            runners={"crt.sh": crtsh, "FuenteIP": ip_source, "theHarvester": harvester, "SpiderFoot": spiderfoot},
            targets=["example.com", "api.example.com", "8.8.8.8"], ip_scope="example.com, *.example.com, 8.8.8.8",
        )
        self.assertEqual(consulted.count(("crt.sh", "example.com")), 1)
        self.assertIn(("crt.sh", "api.example.com"), consulted)
        self.assertEqual([row for row in consulted if row[0] == "theHarvester"], [("theHarvester", "example.com"), ("theHarvester", "api.example.com")])
        self.assertNotIn(("theHarvester", "8.8.8.8"), consulted)
        self.assertIn(("FuenteIP", "8.8.8.8"), consulted)
        self.assertEqual(results["theHarvester"]["contenido"]["hosts"], ["example.com", "api.example.com"])
        self.assertEqual(len(results["SpiderFoot"]["contenido"]), 3)
        self.assertEqual(results["FuenteIP"]["estado"], "completado")
        self.assertEqual(results["FuenteIP"]["ips_en_alcance"], ["198.51.100.7"])
        self.assertIn("api.example.com", results["FuenteIP"]["error"])

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
                "Censys": fails,
                "theHarvester": succeeds,
                "SpiderFoot": succeeds,
            },
        )

        self.assertEqual(set(outcomes), {"crt.sh", "Censys", "theHarvester", "SpiderFoot"})
        self.assertEqual(outcomes["Censys"]["estado"], "fallido")
        self.assertIn("provider unavailable", outcomes["Censys"]["error"])
        for source in ("crt.sh", "theHarvester", "SpiderFoot"):
            self.assertEqual(outcomes[source]["estado"], "completado")
            self.assertEqual(outcomes[source]["contenido"], {"domain": "example.com"})

    async def test_provider_error_does_not_expose_query_credentials(self) -> None:
        async def fails(domain: str) -> None:
            request = httpx.Request(
                "GET", "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8?key=private-key"
            )
            response = httpx.Response(403, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)

        outcomes = await run_all(
            "example.com",
            OrchestratorSettings(),
            runners={"Censys": fails},
        )

        self.assertEqual(outcomes["Censys"]["estado"], "fallido")
        self.assertIn("403", outcomes["Censys"]["error"])
        self.assertNotIn("private-key", outcomes["Censys"]["error"])


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
        self.assertTrue(main._scope_allows_domain("example.com, *.example.com", "api.example.com"))
        self.assertFalse(main._scope_allows_domain("example.com", "api.example.com"))

    def test_target_plan_incluye_subdominios_del_dominio_autorizado_y_omite_ips_ajenas(self) -> None:
        assets = [
            {"tipo": "ip", "valor": "203.0.113.10"},
            {"tipo": "subdominio", "valor": "api.example.com"},
            {"tipo": "subdominio", "valor": "ajeno.net"},
        ]
        scan = {"organizacion_id": "org-1", "autorizacion_id": "auth-1"}
        with patch.object(main, "_execute", side_effect=[{"alcance": "example.com"}, assets]):
            self.assertEqual(main._scan_targets(MagicMock(), scan, "example.com", 20)[0], ["example.com", "api.example.com"])
        with patch.object(main, "_execute", side_effect=[{"alcance": "example.com, *.example.com"}, assets]):
            self.assertEqual(main._scan_targets(MagicMock(), scan, "example.com", 20)[0], ["example.com", "api.example.com"])
        owned_assets = [*assets, {"tipo": "ip", "valor": "8.8.8.8"}, {"tipo": "servicio", "valor": "8.8.8.8:22/tcp"}]
        with patch.object(main, "_execute", side_effect=[{"alcance": "example.com, *.example.com, 8.8.8.8, 203.0.113.10"}, owned_assets]):
            self.assertEqual(
                main._scan_targets(MagicMock(), scan, "example.com", 20, "sfp_baxter_internetdb")[0],
                ["example.com", "api.example.com"],
            )

    def test_target_plan_prioritizes_core_names_and_blocks_unverified_dns_synthetics(self) -> None:
        assets = [
            {"id": "root", "tipo": "dominio", "valor": "example.com"},
            {"id": "z", "tipo": "subdominio", "valor": "z.example.com"},
            {"id": "www", "tipo": "subdominio", "valor": "www.example.com"},
            {"id": "api", "tipo": "subdominio", "valor": "api.example.com"},
            {"id": "dev", "tipo": "subdominio", "valor": "dev.example.com"},
            {"id": "fake", "tipo": "subdominio", "valor": "dmarc.api.example.com"},
            {"id": "real", "tipo": "subdominio", "valor": "mta-sts.example.com"},
        ]
        observations = [
            {"activo_id": "z", "datos": {}, "fuentes_osint": {"nombre": "crt.sh"}},
            {"activo_id": "api", "datos": {}, "fuentes_osint": {"nombre": "crt.sh"}},
            {"activo_id": "dev", "datos": {}, "fuentes_osint": {"nombre": "theHarvester"}},
            {"activo_id": "www", "datos": {"modulo": "sfp_baxter_urlscan"}, "fuentes_osint": {"nombre": "SpiderFoot"}},
            {"activo_id": "fake", "datos": {"modulo": "sfp_dnsresolve"}, "fuentes_osint": {"nombre": "SpiderFoot"}},
            {"activo_id": "real", "datos": {}, "fuentes_osint": {"nombre": "crt.sh"}},
        ]
        scan = {"organizacion_id": "org-1", "autorizacion_id": "auth-1"}
        with patch.object(main, "_execute", side_effect=[
            {"alcance": "example.com, *.example.com"}, assets, observations,
        ]):
            targets, _, excluded = main._scan_targets(MagicMock(), scan, "example.com", 20)
        self.assertEqual(targets[:4], [
            "example.com", "api.example.com", "dev.example.com", "www.example.com",
        ])
        self.assertIn("mta-sts.example.com", targets)
        self.assertNotIn("dmarc.api.example.com", targets)
        self.assertIn("evidencia independiente", excluded["dmarc.api.example.com"])

    def test_thirty_six_historical_dns_synthetics_do_not_consume_the_budget(self) -> None:
        suffixes = ["api", "dev", "www", "dmarc.api", "dmarc.dev", "domainkey.api", "domainkey.dev", "tls.api", "tls.dev"]
        synthetics = [
            {"tipo": "subdominio", "valor": f"{prefix}.{suffix}.example.com"}
            for prefix in ("dmarc", "domainkey", "mta-sts", "tls")
            for suffix in suffixes
        ]
        assets = [
            {"tipo": "dominio", "valor": "example.com"},
            *({"tipo": "subdominio", "valor": f"{name}.example.com"} for name in ("api", "dev", "www")),
            *synthetics,
        ]
        scan = {"organizacion_id": "org-1", "autorizacion_id": "auth-1"}
        with patch.object(main, "_execute", side_effect=[
            {"alcance": "example.com, *.example.com"}, assets,
        ]):
            targets, _, excluded = main._scan_targets(MagicMock(), scan, "example.com", 20)
        self.assertEqual(targets, [
            "example.com", "api.example.com", "dev.example.com", "www.example.com",
        ])
        self.assertEqual(len(excluded), 36)

    def test_execute_responds_202_and_marks_scan_incomplete_when_one_source_fails(self) -> None:
        """El escaneo corre en segundo plano: la respuesta es inmediata y el resultado queda guardado."""
        scan_id = "00000000-0000-0000-0000-000000000001"
        main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-id")
        self.addCleanup(main.app.dependency_overrides.clear)

        settings = SimpleNamespace(
            censys_pat="test-key",
            web_enabled=True,
            theharvester_bin="theHarvester",
            theharvester_sources="crtsh,certspotter",
            spiderfoot_url="http://127.0.0.1:5001",
            spiderfoot_modules="sfp_dnsresolve,sfp_dnsraw,sfp_robtex,sfp_crobat_api",
            request_timeout_seconds=30,
            process_timeout_seconds=900,
            spiderfoot_timeout_seconds=1800,
            spiderfoot_poll_seconds=3,
            scan_timeout_seconds=2100,
            scan_max_hosts=20,
            scan_max_targets=20,
            crtsh_retries=3,
            crtsh_timeout_seconds=60,
            censys_max_ips=10,
            censys_pause_seconds=1.1,
        )
        outcomes = {
            name: {
                "estado": "fallido" if name == "Censys" else "completado",
                "contenido": None if name == "Censys" else [],
                "error": "HTTP 403 from api.platform.censys.io" if name == "Censys" else None,
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

        async def fake_run_all(domain, orchestrator_settings, runners=None, on_result=None, timeout_seconds=None, targets=None, max_targets=None, ip_scope=None, excluded_targets=None):
            for name, outcome in outcomes.items():
                await on_result(name, outcome)
            return outcomes

        with (
            patch.object(main, "get_settings", return_value=settings),
            patch.object(main, "_supabase_client", return_value=object()),
            patch.object(main, "_verify_scope", return_value=({"id": scan_id, "organizacion_id": "org-id"}, "example.com")),
            patch.object(main, "_scan_targets", return_value=(["example.com"], "example.com", {})),
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
        self.assertEqual(persist.call_count, len(main.SOURCE_NAMES))
        self.assertEqual(finish_scan.call_args.args[2], "incompleto")
        risk.assert_called_once()

    def test_detener_exige_escaneo_propio_para_analista_y_devuelve_cancelado(self) -> None:
        scan_id = "00000000-0000-0000-0000-000000000001"
        main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="user-id")
        self.addCleanup(main.app.dependency_overrides.clear)
        results = {name: {"estado": "fallido", "error": "Detenido por el usuario"} for name in main.SOURCE_NAMES}
        with (
            patch.object(main, "_supabase_client", return_value=object()),
            patch.object(main, "_get_profile", return_value={"organizacion_id": "org-id", "rol": "analista"}),
            patch.object(main, "_get_scan", return_value={"id": scan_id, "organizacion_id": "org-id"}) as get_scan,
            patch.object(main, "cancel_scan_job", new=AsyncMock(return_value=True)) as cancel,
            patch.object(main, "_source_results", return_value=results),
            patch.object(main, "_organization_domain", return_value="ejemplo.com"),
            patch.object(main, "audit"),
        ):
            response = TestClient(main.app).post(f"/api/escaneos/{scan_id}/detener")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["estado"], "cancelado")
        self.assertTrue(get_scan.call_args.args[-1])
        cancel.assert_awaited_once()

    def test_detener_no_llama_al_orquestador_si_el_usuario_no_tiene_permiso(self) -> None:
        scan_id = "00000000-0000-0000-0000-000000000001"
        main.app.dependency_overrides[main._current_user] = lambda: SimpleNamespace(id="lector-id")
        self.addCleanup(main.app.dependency_overrides.clear)
        with (
            patch.object(main, "_supabase_client", return_value=object()),
            patch.object(main, "_get_profile", side_effect=main.HTTPException(status_code=403, detail="Sin permiso")),
            patch.object(main, "cancel_scan_job", new=AsyncMock()) as cancel,
        ):
            response = TestClient(main.app).post(f"/api/escaneos/{scan_id}/detener")
        self.assertEqual(response.status_code, 403)
        cancel.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
