"""Prueba real del conector sin escrituras: python -m app.check_censys --domain DOMINIO."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import fields

from app.orchestrators import OrchestratorSettings, run_all, run_censys
from app.osint_normalization import adaptar, normalizar_dominio
from app.settings import get_settings


async def check(domain: str) -> int:
    settings = get_settings()
    config = OrchestratorSettings(**{f.name: getattr(settings, f.name) for f in fields(OrchestratorSettings)})
    results = await run_all(domain, config, runners={"Censys": lambda target: run_censys(target, config)},
                            timeout_seconds=settings.scan_timeout_seconds)
    result = results["Censys"]
    print("Fuente: Censys")
    print("Estado:", result["estado"])
    print("Error:", result["error"])
    if result["estado"] != "completado":
        return 1
    normalized = adaptar("Censys", result["contenido"], domain, result["ips_en_alcance"])
    print("Hosts en Censys:", len(result["contenido"]["hosts"]))
    print("IPs con atribución autorizada:", len(result["ips_en_alcance"]))
    print("Observaciones:", dict(Counter(o["tipo"] + ":" + o["atributo"] for o in normalized["observaciones"])))
    print("Descartadas:", dict(Counter(o["motivo"] for o in normalized["descartadas"])))
    print("No se guardaron datos en Supabase. Un resultado vacío no acredita ausencia de riesgo.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Consulta Censys para un dominio propio/autorizado sin guardar en Supabase")
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()
    normalized = normalizar_dominio(args.domain)
    if normalized is None or normalized[1]:
        parser.error("Usa un dominio sin esquema, ruta ni comodín")
    return asyncio.run(check(normalized[0]))


if __name__ == "__main__":
    raise SystemExit(main())
