from unittest.mock import MagicMock, patch

from app import scan_service
from app.nvd_enrichment import CPE_API, CVE_API, enrich_observations
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo


CPE = "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"


def _cpe_response():
    return {"products": [
        {"cpe": {
            "deprecated": False,
            "cpeName": "cpe:2.3:a:apache:cxf:2.4.7:*:*:*:*:*:*:*",
            "titles": [{"lang": "en", "title": "Apache CXF 2.4.7"}],
        }},
        {"cpe": {
            "deprecated": False,
            "cpeName": CPE,
            "titles": [{"lang": "en", "title": "Apache HTTP Server 2.4.7"}],
        }},
    ]}


def _cve_response():
    cve = {
        "id": "CVE-2021-41773", "published": "2021-10-05T09:15:00.000",
        "lastModified": "2025-11-20T12:00:00.000", "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Controlled fixture"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH",
        }}]},
    }
    return {"totalResults": 1, "vulnerabilities": [{"cve": cve}, {"cve": cve}]}


def test_enrichment_deduplicates_requests_and_preserves_original_evidence():
    calls = []

    def fetch(url, params):
        calls.append((url, params))
        return _cpe_response() if url == CPE_API else _cve_response()

    observations = [
        {
            "tipo": "subdominio", "valor": "scanme.nmap.org", "atributo": "info_host",
            "observado_en": "2026-10-16T00:57:55.862Z",
            "datos": {"tipo_evento": "WEBSERVER_BANNER", "valor": "Apache/2.4.7 (Ubuntu)",
                      "proveedor": "urlscan", "referencias": ["scan-1"]},
        },
        {
            "tipo": "subdominio", "valor": "scanme.nmap.org", "atributo": "info_host",
            "observado_en": "2026-11-18T16:40:20.371Z",
            "datos": {"tipo_evento": "WEBSERVER_BANNER", "valor": "Apache/2.4.7 (Ubuntu)",
                      "proveedor": "urlscan", "referencias": ["scan-2"]},
        },
    ]
    enriched = enrich_observations(observations, "fixture-key", "SpiderFoot", fetch)

    assert [url for url, _ in calls] == [CPE_API, CVE_API]
    assert len(enriched) == 1
    finding = enriched[0]
    assert finding["valor"] == "scanme.nmap.org"
    assert finding["observado_en"] == "2026-11-18T16:40:20.371Z"
    assert finding["datos"]["cve"] == "CVE-2021-41773"
    assert finding["datos"]["verificado"] is False
    assert finding["datos"]["productos_versiones"] == [{
        "producto": "Apache HTTP Server", "version": "2.4.7", "cpe": CPE,
        "resultados_nvd_truncados": False,
    }]
    assert len(finding["datos"]["evidencias_osint"]) == 2
    assert {e["referencias"][0] for e in finding["datos"]["evidencias_osint"]} == {"scan-1", "scan-2"}

    observation = Obs(
        "obs-1", "asset-1", finding["tipo"], finding["valor"], finding["atributo"],
        finding["datos"], "SpiderFoot", "source-1", finding.get("observado_en"),
    )
    rule = Regla("rule-1", "INFRA-003", "CVE", "infraestructura", "alta", 20)
    risk = evaluar_riesgo([observation], [rule], {"SpiderFoot": "completado"})
    assert risk.hallazgos == [] and risk.puntaje.puntaje_global == 0


def test_explicit_cpe_skips_dictionary_lookup_and_missing_version_skips_all_requests():
    calls = []

    def fetch(url, params):
        calls.append((url, params))
        return _cve_response()

    observations = [
        {"tipo": "servicio", "valor": "203.0.113.10:443/tcp", "atributo": "servicio_expuesto",
         "datos": {"producto": "Apache", "version": "2.4.7", "cpe": [CPE]}},
        {"tipo": "subdominio", "valor": "example.com", "atributo": "info_host",
         "datos": {"tipo_evento": "WEBSERVER_TECHNOLOGY", "valor": "Next.js"}},
    ]
    enriched = enrich_observations(observations, "fixture-key", "SpiderFoot", fetch)

    assert len(enriched) == 1
    assert [url for url, _ in calls] == [CVE_API]
    assert calls[0][1]["cpeName"] == CPE


def test_scan_persistence_passes_nvd_key_only_as_ingestion_configuration():
    summary = {
        "resultado_crudo_id": "raw", "ya_procesado": False, "observaciones_generadas": 0,
        "activos_nuevos": 0, "activos_existentes": 0, "observaciones_nuevas": 0,
        "observaciones_duplicadas": 0, "descartadas": {},
    }
    with (
        patch.object(scan_service, "ingestar_resultado", return_value=summary) as ingest,
        patch.object(scan_service, "_execute", return_value=[]),
    ):
        scan_service._persist_source(
            MagicMock(), "org", "scan", "source", "SpiderFoot", "example.com",
            {"estado": "completado", "contenido": [], "error": None},
            nvd_api_key="fixture-key",
        )
    assert ingest.call_args.kwargs["nvd_api_key"] == "fixture-key"
    assert "fixture-key" not in str(ingest.call_args.kwargs["raw"])
