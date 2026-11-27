import unittest
from types import SimpleNamespace
from unittest.mock import patch

from httpx import ConnectError, ReadError

from app.ingestion import _save_raw_result, ingestar_resultado


class FakeQuery:
    def __init__(self, client, table=None, rpc_name=None, rpc_args=None):
        self.client = client
        self.table_name = table
        self.rpc_name = rpc_name
        self.rpc_args = rpc_args
        self.operations = []

    def upsert(self, values, **options):
        self.operations.append(("upsert", values, options))
        return self

    def insert(self, values):
        self.operations.append(("insert", values))
        return self

    def update(self, values):
        self.operations.append(("update", values))
        return self

    def select(self, fields):
        self.operations.append(("select", fields))
        return self

    def eq(self, field, value):
        self.operations.append(("eq", field, value))
        return self

    def single(self):
        return self

    def execute(self):
        if self.rpc_name:
            self.client.rpc_calls.append(self.rpc_args)
            if self.client.rpc_error:
                raise RuntimeError("RPC unavailable")
            item_count = len(self.rpc_args["p_items"])
            return SimpleNamespace(data=[{
                "activos_nuevos": item_count,
                "activos_existentes": 0,
                "observaciones_nuevas": item_count,
                "observaciones_duplicadas": 0,
            }])
        if self.table_name == "resultados_crudos":
            if any(operation[0] == "upsert" for operation in self.operations):
                return SimpleNamespace(data=[{"id": "raw-id", "estado": "pendiente"}])
            self.client.raw_updates.extend(
                operation[1] for operation in self.operations if operation[0] == "update"
            )
        return SimpleNamespace(data=[])


class FakeSupabase:
    def __init__(self, rpc_error=False):
        self.rpc_error = rpc_error
        self.rpc_calls = []
        self.raw_updates = []

    def table(self, name):
        return FakeQuery(self, table=name)

    def rpc(self, name, args):
        return FakeQuery(self, rpc_name=name, rpc_args=args)


class IngestionTests(unittest.TestCase):
    def test_kev_epss_enrichment_runs_after_cve_normalization(self) -> None:
        client = FakeSupabase()
        cve = {"tipo": "subdominio", "valor": "app.example.com", "atributo": "cve",
               "datos": {"cve": "CVE-2021-41773", "verificado": False}}
        enriched = {**cve, "datos": {**cve["datos"], "explotacion": {
            "kev": {"presente": True}, "epss": {"probabilidad": 0.97},
            "modifica_risk_score": False,
        }}}
        with (
            patch("app.ingestion.adaptar", return_value={"observaciones": [cve], "descartadas": []}),
            patch("app.ingestion.enrich_exploitation", return_value=[enriched]) as exploit,
        ):
            summary = ingestar_resultado(
                client, organization_id="org-id", scan_id="scan-id", source_id="source-id",
                source="SpiderFoot", raw=[], domain="example.com", exploit_enrichment=True,
            )
        exploit.assert_called_once_with([cve])
        assert summary["observaciones_generadas"] == 1
        assert client.rpc_calls[0]["p_items"][0]["datos"]["explotacion"]["modifica_risk_score"] is False

    def test_osv_failure_does_not_discard_original_observation(self) -> None:
        client = FakeSupabase()
        original = {
            "tipo": "subdominio", "valor": "app.example.com", "atributo": "info_host",
            "datos": {"paquete": "jinja2", "ecosistema": "PyPI", "version": "2.4.1"},
        }
        with (
            patch("app.ingestion.adaptar", return_value={"observaciones": [original], "descartadas": []}),
            patch("app.ingestion.enrich_observations_osv", side_effect=ConnectError("offline")),
        ):
            summary = ingestar_resultado(
                client, organization_id="org-id", scan_id="scan-id", source_id="source-id",
                source="SpiderFoot", raw=[], domain="example.com",
            )
        assert summary["observaciones_generadas"] == 1
        assert client.rpc_calls[0]["p_items"] == [original]

    def test_nvd_enrichment_is_persisted_as_unverified_without_replacing_evidence(self) -> None:
        client = FakeSupabase()
        original = {
            "tipo": "subdominio", "valor": "scanme.nmap.org", "atributo": "info_host",
            "datos": {"tipo_evento": "WEBSERVER_BANNER", "valor": "Apache/2.4.7"},
        }
        potential = {
            "tipo": "subdominio", "valor": "scanme.nmap.org", "atributo": "cve",
            "datos": {"cve": "CVE-2021-41773", "verificado": False,
                      "fuente_enriquecimiento": "NVD", "evidencias_osint": [{"valor": "Apache/2.4.7"}]},
        }
        with (
            patch("app.ingestion.adaptar", return_value={"observaciones": [original], "descartadas": []}),
            patch("app.ingestion.enrich_observations", return_value=[potential]) as enrich,
        ):
            summary = ingestar_resultado(
                client, organization_id="org-id", scan_id="scan-id", source_id="source-id",
                source="SpiderFoot", raw=[], domain="scanme.nmap.org", nvd_api_key="fixture-key",
            )
        saved = client.rpc_calls[0]["p_items"]
        assert summary["observaciones_generadas"] == 2
        assert {item["atributo"] for item in saved} == {"info_host", "cve"}
        assert next(item for item in saved if item["atributo"] == "cve")["datos"]["verificado"] is False
        enrich.assert_called_once_with([original], "fixture-key", "SpiderFoot")

    def test_resultado_crudo_reintenta_respuesta_perdida_sin_duplicarlo(self) -> None:
        client = FakeSupabase()
        with (patch("app.ingestion._execute", side_effect=[
            ReadError("respuesta cortada"), [], {"id": "raw-id", "estado": "pendiente"},
        ]) as execute, patch("app.ingestion.time.sleep") as sleep):
            raw_id, state = _save_raw_result(client, "scan-id", "source-id", [], "hash")
        self.assertEqual((raw_id, state), ("raw-id", "pendiente"))
        self.assertEqual(execute.call_count, 3)
        sleep.assert_called_once_with(0.5)

    def test_crtsh_real_adapter_persists_subdomain_certificate_and_timestamp(self) -> None:
        client = FakeSupabase()
        raw = {
            "version": 1,
            "entries": [{
                "min_cert_id": 82,
                "min_entry_timestamp": "2026-11-01T12:00:00",
                "serial_number": "abc",
                "name_value": "api.example.com\n*.example.com\noutside.net",
                "not_before": "2026-10-01T00:00:00",
                "not_after": "2027-01-01T00:00:00",
            }],
            "queries": [{"query": "%.example.com", "status": "ok", "entries": 1}],
            "covered_targets": ["example.com", "api.example.com"],
        }
        summary = ingestar_resultado(
            client, organization_id="org-id", scan_id="scan-id", source_id="source-id",
            source="crt.sh", raw=raw, domain="example.com",
        )
        saved = client.rpc_calls[0]["p_items"]
        self.assertEqual(summary["observaciones_generadas"], 4)
        self.assertEqual(summary["descartadas"], {"fuera_de_alcance": 1})
        self.assertEqual({item["valor"] for item in saved}, {"api.example.com", "example.com"})
        self.assertEqual({item["atributo"] for item in saved}, {"descubierto", "certificado"})
        self.assertEqual({item["observado_en"] for item in saved}, {"2026-11-01T12:00:00.000Z"})
        self.assertEqual({item["datos"]["crtsh_id"] for item in saved if item["atributo"] == "certificado"}, {82})

    def test_respuesta_perdida_reintenta_sin_descartar_fuente(self) -> None:
        client = FakeSupabase()
        adapted = {"observaciones": [{"tipo": "subdominio", "valor": "api.example.com", "atributo": "descubierto", "datos": {}}], "descartadas": []}
        counters = {"activos_nuevos": 0, "activos_existentes": 1, "observaciones_nuevas": 0, "observaciones_duplicadas": 1}
        with patch("app.ingestion.adaptar", return_value=adapted), patch(
            "app.ingestion._call_ingestion_rpc", side_effect=[RuntimeError("respuesta perdida"), counters]
        ) as rpc:
            result = ingestar_resultado(
                client, organization_id="org-id", scan_id="scan-id", source_id="source-id",
                source="theHarvester", raw={"hosts": ["api.example.com"]}, domain="example.com",
            )
        self.assertEqual(rpc.call_count, 2)
        self.assertEqual(result["observaciones_generadas"], 1)
        self.assertEqual(result["observaciones_duplicadas"], 1)
        self.assertEqual(client.raw_updates, [])

    def test_batches_observations_and_marks_only_last_batch_processed(self) -> None:
        client = FakeSupabase()
        observations = [
            {"tipo": "subdominio", "valor": f"h{i}.example.com", "atributo": "descubierto", "datos": {}}
            for i in range(1001)
        ]
        adapted = {"observaciones": observations, "descartadas": [{"motivo": "valor_invalido"}]}

        with patch("app.ingestion.adaptar", return_value=adapted):
            summary = ingestar_resultado(
                client,
                organization_id="org-id",
                scan_id="scan-id",
                source_id="source-id",
                source="crt.sh",
                raw=[{"id": 1}],
                domain="example.com",
            )

        self.assertEqual(summary["observaciones_generadas"], 1001)
        self.assertEqual(summary["observaciones_nuevas"], 1001)
        self.assertEqual(summary["descartadas"], {"valor_invalido": 1})
        self.assertEqual(len(client.rpc_calls), 2)
        self.assertEqual(len(client.rpc_calls[0]["p_items"]), 1000)
        self.assertFalse(client.rpc_calls[0]["p_marcar_procesado"])
        self.assertEqual(len(client.rpc_calls[1]["p_items"]), 1)
        self.assertTrue(client.rpc_calls[1]["p_marcar_procesado"])

    def test_rpc_error_marks_raw_result_for_retry(self) -> None:
        client = FakeSupabase(rpc_error=True)
        adapted = {
            "observaciones": [{
                "tipo": "dominio", "valor": "example.com", "atributo": "descubierto", "datos": {}
            }],
            "descartadas": [],
        }

        with patch("app.ingestion.adaptar", return_value=adapted):
            with self.assertRaisesRegex(RuntimeError, "RPC unavailable"):
                ingestar_resultado(
                    client,
                    organization_id="org-id",
                    scan_id="scan-id",
                    source_id="source-id",
                    source="crt.sh",
                    raw=[],
                    domain="example.com",
                )

        self.assertEqual(client.raw_updates, [{"estado": "error"}])


if __name__ == "__main__":
    unittest.main()
