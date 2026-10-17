import unittest

from app.demo import run_demo


class DemoFixtureTests(unittest.TestCase):
    def test_fictional_company_fixture_runs_through_all_adapters(self) -> None:
        result = run_demo()

        self.assertEqual(result["dominio_principal"], "empresa-demo.test")
        self.assertEqual(set(result["fuentes"]), {"crt.sh", "Shodan", "theHarvester", "SpiderFoot"})
        for output in result["fuentes"].values():
            self.assertGreater(output["resumen"]["observaciones_generadas"], 0)
        self.assertIn("sin red", result["modo"])
        self.assertIn("escrituras", result["modo"])


if __name__ == "__main__":
    unittest.main()