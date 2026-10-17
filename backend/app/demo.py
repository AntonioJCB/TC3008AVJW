from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from app.osint_normalization import adaptar


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "empresa_demo_osint.json"


def run_demo(fixture_path: Path = FIXTURE_PATH) -> dict[str, Any]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    domain = fixture["dominio_principal"]
    in_scope_ips = fixture.get("ips_en_alcance", [])
    outputs: dict[str, Any] = {}

    for source, raw in fixture["datos_crudos"].items():
        result = adaptar(source, raw, domain, in_scope_ips)
        outputs[source] = {
            "observaciones": result["observaciones"],
            "descartadas": result["descartadas"],
            "resumen": {
                "observaciones_generadas": len(result["observaciones"]),
                "descartadas_por_motivo": dict(Counter(
                    item["motivo"] for item in result["descartadas"]
                )),
            },
        }
    return {
        "organizacion": fixture["organizacion"],
        "dominio_principal": domain,
        "modo": "offline; sin red ni escrituras en Supabase",
        "fuentes": outputs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Ejecuta los adaptadores con datos OSINT ficticios")
    parser.add_argument(
        "--json",
        action="store_true",
        help="imprime observaciones completas además de los conteos",
    )
    args = parser.parse_args()
    result = run_demo()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    print(f"Demo: {result['organizacion']} ({result['dominio_principal']})")
    print(result["modo"])
    for source, output in result["fuentes"].items():
        summary = output["resumen"]
        print(
            f"- {source}: {summary['observaciones_generadas']} observaciones; "
            f"descartadas={summary['descartadas_por_motivo']}"
        )
    print("Usa --json para ver las observaciones normalizadas completas.")


if __name__ == "__main__":
    main()