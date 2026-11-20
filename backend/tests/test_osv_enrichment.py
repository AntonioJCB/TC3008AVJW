import httpx
import pytest

from app.osv_enrichment import OSV_QUERY_API, enrich_observations_osv
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo
from app.vulnerability_enrichment import merge_potential_vulnerabilities


def package_observation(reference="osint-1"):
    return {
        "tipo": "subdominio", "valor": "app.example.com", "atributo": "info_host",
        "observado_en": "2026-11-18T12:00:00Z",
        "datos": {
            "tipo_evento": "PACKAGE_VERSION", "paquete": "jinja2", "ecosistema": "PyPI",
            "version": "2.4.1", "proveedor": "fixture", "referencias": [reference],
        },
    }


def osv_response():
    return {"vulns": [{
        "id": "GHSA-462W-V97R-4M45", "aliases": ["CVE-2019-10906"],
        "published": "2019-04-07T00:00:00Z", "modified": "2024-11-18T00:00:00Z",
        "summary": "Controlled fixture", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
    }]}


def test_osv_requires_explicit_package_ecosystem_version_and_deduplicates_queries():
    calls = []

    def fetch(payload):
        calls.append(payload)
        return osv_response()

    enriched = enrich_observations_osv(
        [package_observation("osint-1"), package_observation("osint-2")], "SpiderFoot", fetch,
    )
    assert calls == [{"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.4.1"}]
    assert len(enriched) == 1
    finding = enriched[0]
    assert finding["datos"]["cve"] == "CVE-2019-10906"
    assert finding["datos"]["verificado"] is False
    assert finding["datos"]["paquetes_versiones"] == [{"paquete": "jinja2", "ecosistema": "PyPI", "version": "2.4.1"}]
    assert len(finding["datos"]["evidencias_osint"]) == 2
    assert OSV_QUERY_API == "https://api.osv.dev/v1/query"

    observation = Obs("o", "a", finding["tipo"], finding["valor"], "cve", finding["datos"], "SpiderFoot", "sf")
    rule = Regla("r", "INFRA-003", "CVE", "infraestructura", "alta", 20)
    risk = evaluar_riesgo([observation], [rule], {"SpiderFoot": "completado"})
    assert risk.hallazgos == [] and risk.puntaje.puntaje_global == 0


def test_osv_empty_incomplete_and_error_responses_are_distinct():
    assert enrich_observations_osv([package_observation()], "SpiderFoot", lambda _: {"vulns": []}) == []
    called = []
    incomplete = package_observation()
    del incomplete["datos"]["ecosistema"]
    assert enrich_observations_osv([incomplete], "SpiderFoot", lambda payload: called.append(payload) or osv_response()) == []
    assert called == []
    with pytest.raises(httpx.ConnectError):
        enrich_observations_osv(
            [package_observation()], "SpiderFoot",
            lambda _: (_ for _ in ()).throw(httpx.ConnectError("offline")),
        )


def test_osv_and_nvd_same_cve_merge_references_without_becoming_verified():
    nvd = {
        "tipo": "subdominio", "valor": "app.example.com", "atributo": "cve",
        "datos": {"cve": "CVE-2019-10906", "verificado": False, "fuente_enriquecimiento": "NVD",
                  "fuentes_enriquecimiento": ["NVD"], "nvd": {"referencia": "https://nvd.test/CVE-2019-10906"},
                  "referencias_enriquecimiento": ["https://nvd.test/CVE-2019-10906"],
                  "evidencias_osint": [{"referencias": ["osint-1"]}]},
    }
    osv = enrich_observations_osv([package_observation()], "SpiderFoot", lambda _: osv_response())[0]
    merged = merge_potential_vulnerabilities([nvd, osv])
    assert len(merged) == 1
    details = merged[0]["datos"]
    assert details["fuentes_enriquecimiento"] == ["NVD", "OSV"]
    assert details["verificado"] is False
    assert details["nvd"] and details["osv"]
    assert "https://nvd.test/CVE-2019-10906" in details["referencias_enriquecimiento"]
    assert "https://osv.dev/vulnerability/GHSA-462W-V97R-4M45" in details["referencias_enriquecimiento"]
