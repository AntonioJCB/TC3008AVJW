import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.ingestion import ingestar_resultado


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