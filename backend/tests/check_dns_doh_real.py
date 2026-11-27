"""Run only BaxterSec DNS DoH through the real local SpiderFoot service.

This checker never writes Supabase. Pass only names already verified against a
current authorization, for example:

    python backend/tests/check_dns_doh_real.py example.com api.example.com
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.orchestrators import OrchestratorSettings, run_spiderfoot  # noqa: E402
from app.osint_normalization import adaptar, normalizar_dominio  # noqa: E402
from app.spiderfoot_passive import reports  # noqa: E402


async def check(root_domain: str, targets: list[str]) -> dict[str, object]:
    settings = OrchestratorSettings(
        spiderfoot_url="http://127.0.0.1:5001",
        spiderfoot_modules="sfp_baxter_dns_doh",
        request_timeout_seconds=30,
        spiderfoot_timeout_seconds=300,
        spiderfoot_poll_seconds=1,
    )
    checked = []
    for target in targets:
        print(f"START {datetime.now(timezone.utc).isoformat()} {target}", file=sys.stderr, flush=True)
        output = await run_spiderfoot(target, settings)
        provider_reports = reports(output.data)
        if len(provider_reports) != 1:
            diagnostic = [
                {key: row.get(key) for key in ("module", "event_type", "type", "data", "source_data", "scan_target")}
                for row in output.data[:20] if isinstance(row, dict)
            ] if isinstance(output.data, list) else {"tipo": type(output.data).__name__}
            raise RuntimeError(json.dumps({
                "target": target,
                "expected_reports": 1,
                "received_reports": len(provider_reports),
                "orchestrator_error": output.error,
                "raw_event_count": len(output.data) if isinstance(output.data, list) else None,
                "raw_sample": diagnostic,
            }, ensure_ascii=False))
        report = provider_reports[0]
        normalized = adaptar("SpiderFoot", output.data, root_domain)
        checks = {row["check"]: row for row in report.get("checks", [])}
        checked.append({
            "target": target,
            "status": report["status"],
            "provider_results": report["results"],
            "source_error": output.error,
            "check_states": {key: value["state"] for key, value in checks.items()},
            "record_counts": {key: len(value["records"]) for key, value in checks.items()},
            "issues": [
                {"check": key, **issue}
                for key, value in checks.items()
                for issue in value.get("issues", [])
            ],
            "observations": len(normalized["observaciones"]),
            "observation_assets": sorted({row["valor"] for row in normalized["observaciones"]}),
            "discarded": normalized["descartadas"],
        })
        print(f"FINISH {datetime.now(timezone.utc).isoformat()} {target} {report['status']}", file=sys.stderr, flush=True)
    return {
        "mode": "passive-real-provider-no-supabase-write",
        "module": "sfp_baxter_dns_doh",
        "root_domain": root_domain,
        "targets": checked,
    }


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Indica al menos un dominio autorizado")
    parsed = [normalizar_dominio(value) for value in sys.argv[1:]]
    if any(value is None or value[1] for value in parsed):
        raise SystemExit("Todos los objetivos deben ser nombres DNS válidos sin comodines")
    names = [value[0] for value in parsed if value]
    root_domain = names[0]
    if any(name != root_domain and not name.endswith(f".{root_domain}") for name in names):
        raise SystemExit("Todos los objetivos deben pertenecer al primer dominio indicado")
    print(json.dumps(asyncio.run(check(root_domain, names)), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
