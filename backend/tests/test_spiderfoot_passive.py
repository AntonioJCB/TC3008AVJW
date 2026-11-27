"""Synthetic provider fixtures: no network, credentials or shared database."""
import asyncio
import importlib.util
import json
import sys
import threading
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from app import orchestrators
from app.osint_normalization import adaptar
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo
from app.risk.reglas import DEFINICIONES
from app.scan_report import build_coverage
from app.source_policy import RETIRED_RISK_RULES
from app.spiderfoot_passive import (
    COMMONCRAWL_RDAP_DEFAULT_MODULES,
    DEFAULT_MODULES,
    DNS_QUERIES,
    LEGACY_MODULES,
    collect,
    report_chunks,
    reports,
    selected_modules,
    serialize_report_chunk,
    unavailable_report_event,
)

IP = "8.8.8.8"  # Fixture identity only. No real request is made.
NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
RULES = [Regla("ssh", "INFRA-001", "SSH", "infraestructura", "alta", 15),
         Regla("db", "INFRA-002", "DB", "infraestructura", "critica", 30),
         Regla("cve", "INFRA-003", "CVE", "infraestructura", "media", 8)]


def export(report, **extra):
    modules = {"google_dns_doh": "sfp_baxter_dns_doh", "common_crawl": "sfp_baxter_commoncrawl", "rdap": "sfp_baxter_rdap"}
    return {"event_type": "RAW_RIR_DATA", "data": json.dumps(report),
            "module": modules.get(report["provider"], "sfp_baxter_" + report["provider"]), "source_data": report["target"],
            "scan_target": report["target"], "false_positive": 0, **extra}




def normalized(report):
    return adaptar("SpiderFoot", [export(report)], "example.com")["observaciones"]


def score(rows):
    observations = [Obs(str(i), row["valor"], row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf") for i, row in enumerate(rows)]
    return evaluar_riesgo(observations, RULES, {"SpiderFoot": "completado"}, NOW).puntaje.puntaje_global


def dns_fetch(records=None, failures=None, ad=False, statuses=None):
    records, failures, statuses = records or {}, failures or set(), statuses or {}
    def fetch(_url, params):
        key = (params["name"], params["type"])
        if key in failures:
            return 503, {}
        answers = [{"name": params["name"] + ".", "type": type_id, "TTL": 300, "data": value}
                   for type_id, value in records.get(key, [])]
        return 200, {"Status": statuses.get(key, 0), "AD": ad, "Answer": answers}
    return fetch


@pytest.mark.parametrize("provider,target,kwargs", [
    ("urlscan", "api.example.com", {}), ("common_crawl", "api.example.com", {})])
@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_http_failure_never_becomes_empty(provider, target, kwargs, status):
    result = collect(provider, target, lambda *_: (status, {}), **kwargs)
    assert result["status"] == "error" and result["events"] == []
    assert "test-secret" not in json.dumps(result)


@pytest.mark.parametrize("body", [None, [], {}, {"results": "oops"}])
def test_bad_json_schema_is_failure(body):
    result = collect("urlscan", "example.com", lambda *_: (200, body))
    assert result["status"] == "error"


def test_urlscan_exact_asset_and_historical_timestamp_no_dns_inference():
    fetch = Mock(return_value=(200, {"results": [
        {"page": {"domain": "api.example.com", "server": "nginx/1.2", "ip": IP}, "task": {"time": "2026-11-01T12:00:00Z"}, "_id": "fixture"},
        {"page": {"domain": "example.com", "server": "foreign"}},
        {"page": {"domain": "neighbor.example.net", "server": "foreign"}}]}))
    result = collect("urlscan", "api.example.com", fetch)
    rows = normalized(result)
    assert result["results"] == 1 and score(rows) == 0
    assert {row["valor"] for row in rows} == {"api.example.com"}
    assert {row["atributo"] for row in rows} == {"info_host"}
    assert all(row["observado_en"] == "2026-11-01T12:00:00.000Z" for row in rows)
    assert fetch.call_args.args[0] == "https://urlscan.io/api/v1/search/"
    assert fetch.call_args.args[1] == {"q": '(page.domain.keyword:"api.example.com" OR task.domain.keyword:"api.example.com")', "size": 100, "datasource": "scans"}
    assert "response" not in result


def test_urlscan_truncated_history_is_partial():
    result = collect("urlscan", "example.com", lambda *_: (200, {"results": [], "total": 200, "has_more": True, "search_date_limit_days": 30}))
    assert result["status"] == "partial"
    assert result["search_date_limit_days"] == 30 and "30 días" in " ".join(result["limitations"])


def test_urlscan_consolidates_technical_history_without_claiming_vulnerabilities():
    def row(scan_id, when, **page):
        return {"_id": scan_id, "task": {"time": when, "url": "https://api.example.com/start"},
                "page": {"domain": "api.example.com", **page},
                "content": {"technologies": ["Next.js", "React 18"]}}
    data = {"search_date_limit_days": 14, "results": [
        row("one", "2026-11-01T00:00:00Z", server="Vercel", status="200", redirected="https-only",
            url="https://api.example.com/", ip="203.0.113.10", asn="AS1", mimeType="text/html",
            tlsIssuer="Fixture CA", tlsValidFrom="2026-10-01T00:00:00Z", tlsValidDays=90),
        row("two", "2026-11-03T00:00:00Z", server="Vercel", status="200", redirected="https-only",
            url="https://api.example.com/", ip="203.0.113.10", asn="AS1", mimeType="text/html",
            tlsIssuer="Fixture CA", tlsValidFrom="2026-10-01T00:00:00Z", tlsValidDays=90),
        {"_id": "three", "task": {"time": "2026-11-04T00:00:00Z", "url": "https://api.example.com/"},
         "page": {"domain": "login.provider.net", "url": "https://login.provider.net/", "server": "foreign", "redirected": "off-domain"},
         "content": {"technologies": ["ForeignTech"]}},
        {"page": {"domain": "neighbor.example.net", "server": "foreign"}}, None,
    ]}
    result = collect("urlscan", "api.example.com", lambda *_: (200, data))
    assert result["status"] == "partial" and result["results"] == 3
    events = {(event["event_type"], event["data"]): event for event in result["events"]}
    history = events[("URLSCAN_HISTORY", "api.example.com")]
    assert history["metadata"]["ocurrencias"] == 3
    assert history["metadata"]["fechas"] == ["2026-11-01T00:00:00Z", "2026-11-03T00:00:00Z", "2026-11-04T00:00:00Z"]
    assert history["metadata"]["referencias"] == ["one", "two", "three"]
    assert events[("WEBSERVER_BANNER", "Vercel")]["metadata"]["ocurrencias"] == 2
    assert ("WEBSERVER_BANNER", "foreign") not in events and ("WEBSERVER_TECHNOLOGY", "ForeignTech") not in events
    assert events[("WEBSERVER_TECHNOLOGY", "Next.js")]["metadata"]["evaluable"] is False
    assert any(kind == "URLSCAN_TLS_CERTIFICATE" for kind, _value in events)
    assert any(kind == "URLSCAN_REDIRECT" and value == "off-domain" for kind, value in events)
    assert score(normalized(result)) == 0

    chunks = report_chunks(result)
    assert max(len(json.dumps(chunk)) for chunk in chunks) < 1400
    raw = [{"event_type": "RAW_RIR_DATA", "data": json.dumps(chunk), "module": "sfp_baxter_urlscan",
            "scan_target": "api.example.com", "source_data": "api.example.com", "false_positive": 0}
           for chunk in chunks]
    rebuilt = reports(raw)
    assert len(rebuilt) == 1 and len(rebuilt[0]["events"]) == len(result["events"])


def test_urlscan_missing_rows_are_partial_not_zero_or_fabricated():
    result = collect("urlscan", "example.com", lambda *_: (200, {"results": [None]}))
    assert result["status"] == "partial" and result["results"] == 0 and result["events"] == []


def _urlscan_header_fixture(headers, *, when="2026-11-18T12:00:00Z", host="api.example.com",
                            status=200, mime="text/html", scan_id="header-fixture"):
    url = f"https://{host}/"
    search = {"results": [{"_id": scan_id, "task": {"time": when, "url": url},
                            "page": {"domain": host, "url": url, "status": status, "mimeType": mime}}]}
    detail = {"page": {"domain": host, "url": url, "status": status, "mimeType": mime},
              "data": {"requests": [{"response": {"response": {
                  "url": url, "status": status, "mimeType": mime, "headers": headers,
              }}}]}}
    return search, detail


def _collect_urlscan_headers(search, details):
    def fetch(url, _params):
        return (200, search) if url.endswith("/search/") else (200, details[url.split("/")[-2]])
    return collect("urlscan", "api.example.com", fetch, api_key="fixture-key")


def _conf004_result(report, active=True):
    observations = [Obs(str(index), "asset-api", row["tipo"], row["valor"], row["atributo"],
                        row["datos"], "SpiderFoot", "sf", row.get("observado_en"))
                    for index, row in enumerate(normalized(report))]
    rule = Regla("conf004", "CONF-004", "Cabeceras ausentes", "configuracion", "baja", 5, active)
    return evaluar_riesgo(observations, [rule], {"SpiderFoot": "completado"}, NOW)


def test_conf004_uses_complete_recent_exact_https_html_response():
    search, detail = _urlscan_header_fixture({"Content-Type": "text/html", "Server": "fixture"})
    result = _collect_urlscan_headers(search, {"header-fixture": detail})
    event = next(event for event in result["events"] if event["event_type"] == "URLSCAN_SECURITY_HEADERS")
    assert event["metadata"]["cabeceras_completas"] is True
    assert event["metadata"]["evaluable"] is True
    assert {issue["code"] for issue in event["metadata"]["issues"]} == {
        "HTTP_HEADER_STRICT_TRANSPORT_SECURITY", "HTTP_HEADER_CONTENT_SECURITY_POLICY",
        "HTTP_HEADER_X_CONTENT_TYPE_OPTIONS", "HTTP_HEADER_CLICKJACKING_PROTECTION",
    }
    inactive = _conf004_result(result, active=False)
    assert len(inactive.hallazgos) == 1 and inactive.puntaje.puntaje_global == 0
    assert inactive.hallazgos[0].nivel_evidencia == "potencial"
    assert inactive.puntaje.cobertura["riesgo_potencial"]["reglas_inactivas"]["hallazgos"] == 1
    active = _conf004_result(result)
    assert len(active.hallazgos) == 1
    finding = active.hallazgos[0]
    assert finding.severidad == "baja" and active.puntaje.puntaje_global == 0
    assert finding.evidencia["aporte_potencial_estimado"] == 4.3
    assert finding.evidencia["detalle"]["potencial"] is True
    assert finding.evidencia["detalle"]["verificado_actual"] is False
    assert finding.evidencia["detalle"]["referencias"] == ["https://urlscan.io/result/header-fixture/"]


def test_conf004_complete_headers_are_negative_and_csp_frame_ancestors_replaces_xfo():
    headers = {"Content-Type": "text/html", "Strict-Transport-Security": "max-age=31536000",
               "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
               "X-Content-Type-Options": "nosniff"}
    search, detail = _urlscan_header_fixture(headers)
    result = _collect_urlscan_headers(search, {"header-fixture": detail})
    event = next(event for event in result["events"] if event["event_type"] == "URLSCAN_SECURITY_HEADERS")
    assert event["metadata"]["issues"] == []
    assert _conf004_result(result).hallazgos == []


@pytest.mark.parametrize("mutation", ["missing_headers", "http", "non_html", "redirect", "foreign"])
def test_conf004_incomplete_or_inapplicable_result_never_scores(mutation):
    search, detail = _urlscan_header_fixture({"Content-Type": "text/html"})
    response = detail["data"]["requests"][0]["response"]["response"]
    if mutation == "missing_headers":
        response.pop("headers")
    elif mutation == "http":
        search["results"][0]["page"]["url"] = detail["page"]["url"] = response["url"] = "http://api.example.com/"
    elif mutation == "non_html":
        search["results"][0]["page"]["mimeType"] = detail["page"]["mimeType"] = response["mimeType"] = "image/png"
    elif mutation == "redirect":
        search["results"][0]["page"]["status"] = detail["page"]["status"] = response["status"] = 302
    else:
        detail["page"]["domain"] = "foreign.example.net"
        detail["page"]["url"] = response["url"] = "https://foreign.example.net/"
    result = _collect_urlscan_headers(search, {"header-fixture": detail})
    assert _conf004_result(result).hallazgos == []
    header_events = [event for event in result["events"] if event["event_type"] == "URLSCAN_SECURITY_HEADERS"]
    if mutation in {"missing_headers", "http", "foreign"}:
        assert header_events == []
    else:
        assert header_events[0]["metadata"]["evaluable"] is False


def test_conf004_stale_or_superseded_absence_does_not_score():
    old_search, old_detail = _urlscan_header_fixture(
        {"Content-Type": "text/html"}, when="2026-01-01T00:00:00Z", scan_id="old")
    recent_headers = {"Content-Type": "text/html", "Strict-Transport-Security": "max-age=1",
                      "Content-Security-Policy": "frame-ancestors 'none'", "X-Content-Type-Options": "nosniff"}
    new_search, new_detail = _urlscan_header_fixture(
        recent_headers, when="2026-11-18T12:00:00Z", scan_id="new")
    search = {"results": [old_search["results"][0], new_search["results"][0]]}
    result = _collect_urlscan_headers(search, {"old": old_detail, "new": new_detail})
    events = [event for event in result["events"] if event["event_type"] == "URLSCAN_SECURITY_HEADERS"]
    assert len(events) == 2
    assert any(event["metadata"]["evaluable"] is False and event["metadata"]["antiguedad_dias"] > 90
               for event in events)
    assert _conf004_result(result).hallazgos == []


def _urlscan_redirect_fixture(*, initial="http://api.example.com/", final=None, redirects=None,
                              when="2026-11-18T12:00:00Z", status=200, mime="text/html",
                              scan_id="redirect-fixture"):
    final = final or initial
    search = {"results": [{"_id": scan_id, "task": {"time": when, "url": initial},
                            "page": {"domain": (final.split("//", 1)[-1].split("/", 1)[0]),
                                     "url": final, "status": status, "mimeType": mime}}]}
    detail = {"task": {"time": when, "url": initial, "uuid": scan_id},
              "page": {"domain": (final.split("//", 1)[-1].split("/", 1)[0]),
                       "url": final, "status": status, "mimeType": mime},
              "data": {"redirects": redirects if redirects is not None else [], "requests": []}}
    return search, detail


def _conf008_result(report, active=True):
    observations = [Obs(str(index), "asset-api", row["tipo"], row["valor"], row["atributo"],
                        row["datos"], "SpiderFoot", "sf", row.get("observado_en"))
                    for index, row in enumerate(normalized(report))]
    rule = Regla("conf008", "CONF-008", "HTTP sin HTTPS", "configuracion", "media", 6, active)
    return evaluar_riesgo(observations, [rule], {"SpiderFoot": "completado"}, NOW)


def test_conf008_explicit_recent_http_2xx_without_redirect_is_potential_only_while_inactive():
    search, detail = _urlscan_redirect_fixture()
    result = _collect_urlscan_headers(search, {"redirect-fixture": detail})
    event = next(event for event in result["events"] if event["event_type"] == "URLSCAN_HTTP_REDIRECT")
    assert event["metadata"]["estado"] == "http_sin_redireccion_https"
    assert event["metadata"]["cadena_completa"] is True and event["metadata"]["evaluable"] is True
    inactive = _conf008_result(result, active=False)
    assert len(inactive.hallazgos) == 1 and inactive.puntaje.puntaje_global == 0
    assert inactive.hallazgos[0].nivel_evidencia == "potencial"
    assert "CONF-008" not in RETIRED_RISK_RULES
    candidate = _conf008_result(result)
    assert len(candidate.hallazgos) == 1 and candidate.puntaje.puntaje_global == 0
    assert candidate.hallazgos[0].evidencia["detalle"]["potencial"] is True
    assert candidate.hallazgos[0].evidencia["detalle"]["verificado_actual"] is False


def test_conf008_never_consumes_historical_web_observations():
    observation = Obs("web-old", "asset-api", "subdominio", "api.example.com", "info_host",
                      {"check": "http_sin_redireccion"}, "Web", "web")
    rule = Regla("conf008", "CONF-008", "HTTP sin HTTPS", "configuracion", "media", 6, True)
    result = evaluar_riesgo([observation], [rule], {"Web": "completado"}, NOW)
    assert result.hallazgos == [] and result.puntaje.puntaje_global == 0


def test_conf008_explicit_same_host_https_redirect_is_negative():
    search, detail = _urlscan_redirect_fixture(
        final="https://api.example.com/",
        redirects=[{"url": "http://api.example.com/", "type": "http"}],
    )
    result = _collect_urlscan_headers(search, {"redirect-fixture": detail})
    event = next(event for event in result["events"] if event["event_type"] == "URLSCAN_HTTP_REDIRECT")
    assert event["metadata"]["estado"] == "redirige_a_https"
    assert event["metadata"]["issues"] == [] and _conf008_result(result).hallazgos == []


@pytest.mark.parametrize("case", ["missing_chain", "foreign_final", "non_html", "redirect_status", "https_direct"])
def test_conf008_incomplete_or_inapplicable_evidence_never_scores(case):
    initial, final, redirects, status, mime = "http://api.example.com/", None, [], 200, "text/html"
    if case == "foreign_final":
        final = "https://other.example.net/"
        redirects = [{"url": initial}]
    elif case == "non_html":
        mime = "application/json"
    elif case == "redirect_status":
        status = 302
    elif case == "https_direct":
        initial = final = "https://api.example.com/"
    search, detail = _urlscan_redirect_fixture(
        initial=initial, final=final, redirects=redirects, status=status, mime=mime)
    if case == "missing_chain":
        detail["data"].pop("redirects")
    result = _collect_urlscan_headers(search, {"redirect-fixture": detail})
    assert _conf008_result(result).hallazgos == []
    events = [event for event in result["events"] if event["event_type"] == "URLSCAN_HTTP_REDIRECT"]
    if case in {"missing_chain", "foreign_final", "non_html", "redirect_status"}:
        assert events == []
    else:
        assert events[0]["metadata"]["estado"] == "https_directo"


def test_conf008_stale_or_newer_secure_redirect_suppresses_historical_candidate():
    old_search, old_detail = _urlscan_redirect_fixture(
        when="2026-01-01T00:00:00Z", scan_id="old-http")
    new_search, new_detail = _urlscan_redirect_fixture(
        final="https://api.example.com/", redirects=[{"url": "http://api.example.com/"}],
        when="2026-11-18T12:00:00Z", scan_id="new-https")
    search = {"results": [old_search["results"][0], new_search["results"][0]]}
    result = _collect_urlscan_headers(search, {"old-http": old_detail, "new-https": new_detail})
    assert _conf008_result(result).hallazgos == []
    events = [event for event in result["events"] if event["event_type"] == "URLSCAN_HTTP_REDIRECT"]
    assert len(events) == 2
    assert any(event["metadata"]["antiguedad_dias"] > 90 and event["metadata"]["evaluable"] is False
               for event in events)


def test_conf006_ct_urlscan_and_unmarked_historical_web_evidence_never_score():
    search = {"results": [{"_id": "tls-history", "task": {"time": "2026-11-18T12:00:00Z"},
                           "page": {"domain": "api.example.com", "url": "https://api.example.com/",
                                    "status": 200, "mimeType": "text/html", "tlsIssuer": "Fixture CA",
                                    "tlsValidFrom": "2026-01-01T00:00:00Z", "tlsValidDays": 90}}]}
    spiderfoot_rows = normalized(collect("urlscan", "api.example.com", lambda *_: (200, search)))
    crt_rows = adaptar("crt.sh", {"version": 1, "entries": [{
        "id": 1, "name_value": "api.example.com", "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2025-04-01T00:00:00Z",
    }], "queries": []}, "example.com")["observaciones"]
    observations = [
        Obs(f"sf-{index}", "asset-api", row["tipo"], row["valor"], row["atributo"],
            row["datos"], "SpiderFoot", "sf", row.get("observado_en"))
        for index, row in enumerate(spiderfoot_rows)
    ] + [
        Obs(f"ct-{index}", "asset-api", row["tipo"], row["valor"], row["atributo"],
            row["datos"], "crt.sh", "ct", row.get("observado_en"))
        for index, row in enumerate(crt_rows)
    ] + [
        Obs("web-old", "asset-api", "subdominio", "api.example.com", "info_host",
            {"check": "tls_invalido", "verify_code": 10}, "Web", "web")
    ]
    rule = Regla("conf006", "CONF-006", "TLS inválido", "configuracion", "media", 12, True)
    risk = evaluar_riesgo(observations, [rule],
                          {"SpiderFoot": "completado", "crt.sh": "completado", "Web": "completado"}, NOW)
    assert any(row["datos"].get("tipo_evento") == "URLSCAN_TLS_CERTIFICATE" for row in spiderfoot_rows)
    assert risk.hallazgos == [] and risk.puntaje.puntaje_global == 0
    assert risk.puntaje.cobertura["no_evaluadas"] == []


def _conf007_result(report, active=True, extra=None, *, now=datetime(2026, 11, 20, tzinfo=timezone.utc)):
    rows = normalized(report)
    observations = [Obs(str(index), "asset-api", row["tipo"], row["valor"], row["atributo"],
                        row["datos"], "SpiderFoot", "sf", row.get("observado_en"))
                    for index, row in enumerate(rows)]
    observations.extend(extra or [])
    rule = Regla("conf007", "CONF-007", "Certificado próximo", "configuracion", "baja", 4, active)
    return evaluar_riesgo(observations, [rule], {"SpiderFoot": "completado", "Web": "completado"}, now)


def _urlscan_tls_report(*, when="2026-11-18T12:00:00Z", valid_from="2026-10-01T00:00:00Z",
                        valid_days=55, tls_age=48, scan_id="tls-near"):
    page = {"domain": "api.example.com", "url": "https://api.example.com/", "status": 200,
            "mimeType": "text/html", "tlsIssuer": "Fixture CA", "tlsValidFrom": valid_from}
    if valid_days is not None:
        page["tlsValidDays"] = valid_days
    if tls_age is not None:
        page["tlsAgeDays"] = tls_age
    data = {"results": [{"_id": scan_id, "task": {"time": when}, "page": page}]}
    return collect("urlscan", "api.example.com", lambda *_: (200, data))


def test_conf007_recent_exact_urlscan_certificate_is_only_potential_while_inactive():
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 20, tzinfo=tz or timezone.utc)
    with patch('app.spiderfoot_passive.datetime', FrozenDateTime):
        report = _urlscan_tls_report()
    event = next(event for event in report["events"] if event["event_type"] == "URLSCAN_TLS_CERTIFICATE")
    assert event["metadata"]["evidencia_completa"] is True
    assert event["metadata"]["evaluable"] is True and 0 < event["metadata"]["dias_restantes"] <= 14
    for active in (False, True):
        result = _conf007_result(report, active=active)
        assert len(result.hallazgos) == 1
        assert result.hallazgos[0].nivel_evidencia == "potencial"
        assert result.hallazgos[0].evidencia["detalle"]["verificado_actual"] is False
        assert result.puntaje.puntaje_global == 0
        assert result.puntaje.cobertura["riesgo_potencial"]["puntaje_global"] > 0
    assert DEFINICIONES["CONF-007"].requiere_fuentes == ("SpiderFoot", "Web")
    assert "CONF-007" not in RETIRED_RISK_RULES


def test_conf007_recalculo_rechaza_evidencia_caduca_o_futura():
    report = _urlscan_tls_report()
    assert _conf007_result(report, now=datetime(2026, 11, 26, tzinfo=timezone.utc)).hallazgos == []
    assert _conf007_result(report, now=NOW).hallazgos == []


@pytest.mark.parametrize("kwargs", [
    {"valid_days": None},
    {"when": "2026-09-01T00:00:00Z", "tls_age": None},
    {"tls_age": 2},
    {"valid_days": 365},
    {"valid_days": 30},
])
def test_conf007_incomplete_stale_incoherent_safe_or_expired_evidence_never_scores(kwargs):
    report = _urlscan_tls_report(**kwargs)
    assert _conf007_result(report).hallazgos == []


def test_conf007_newer_safe_urlscan_and_historical_web_or_crt_do_not_score():
    near = _urlscan_tls_report(when="2026-11-17T12:00:00Z", scan_id="near")
    safe = _urlscan_tls_report(when="2026-11-19T12:00:00Z", valid_days=365, tls_age=49, scan_id="safe")
    search = {"results": [
        {"_id": "near", "task": {"time": "2026-11-17T12:00:00Z"},
         "page": {"domain": "api.example.com", "url": "https://api.example.com/", "status": 200,
                  "mimeType": "text/html", "tlsIssuer": "Fixture CA", "tlsValidFrom": "2026-10-01T00:00:00Z",
                  "tlsValidDays": 55, "tlsAgeDays": 47}},
        {"_id": "safe", "task": {"time": "2026-11-19T12:00:00Z"},
         "page": {"domain": "api.example.com", "url": "https://api.example.com/", "status": 200,
                  "mimeType": "text/html", "tlsIssuer": "Fixture CA", "tlsValidFrom": "2026-10-01T00:00:00Z",
                  "tlsValidDays": 365, "tlsAgeDays": 49}},
    ]}
    report = collect("urlscan", "api.example.com", lambda *_: (200, search))
    extra = [
        Obs("web-old", "asset-api", "subdominio", "api.example.com", "info_host",
            {"check": "tls_por_expirar", "valid_until": "2026-11-25T00:00:00Z"}, "Web", "web"),
        Obs("ct-old", "asset-api", "subdominio", "api.example.com", "certificado",
            {"valido_hasta": "2026-11-25T00:00:00Z"}, "crt.sh", "ct"),
    ]
    assert near["events"] and safe["events"]
    assert _conf007_result(report, extra=extra).hallazgos == []


def test_commoncrawl_exact_host_deduplicates_history_and_never_scores():
    catalog = [
        {"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index",
         "from": "2026-10-05T00:00:00", "to": "2026-10-18T00:00:00"},
        {"id": "CC-MAIN-2026-39", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-39-index",
         "from": "2026-09-04T00:00:00", "to": "2026-09-17T00:00:00"},
    ]
    first = [
        {"url": "https://api.example.com/manual.pdf", "timestamp": "20261010120000", "status": "200",
         "mime": "application/pdf", "digest": "DIGEST1", "filename": "crawl/one.warc.gz", "offset": "10", "length": "20"},
        {"url": "https://api.example.com/backup.sql", "timestamp": "20261011120000", "status": "403",
         "mime-detected": "text/html", "digest": "DIGEST2"},
    ]
    second = [
        {"url": "https://api.example.com/manual.pdf", "timestamp": "20260910120000", "status": "200",
         "mime": "application/pdf", "digest": "DIGEST0"},
        {"url": "https://api.example.com/api/openapi.json", "timestamp": "20260912120000", "status": "200",
         "mime": "application/json", "digest": "DIGEST3"},
    ]
    calls = []
    def fetch(url, params):
        calls.append((url, params))
        if url.endswith("collinfo.json"):
            return 200, catalog
        return 200, first if "2026-43" in url else second

    result = collect("common_crawl", "api.example.com", fetch, commoncrawl_indexes=2, commoncrawl_max_results=10)
    assert result["status"] == "ok" and result["results"] == 4 and result["unique_urls"] == 3
    assert len(calls) == 3
    assert all(call[1].get("matchType") == "host" and call[1].get("url") == "api.example.com"
               and call[1].get("limit") == 10 for call in calls[1:])
    events = {event["data"]: event for event in result["events"]}
    manual = events["https://api.example.com/manual.pdf"]
    assert manual["metadata"]["ocurrencias"] == 2
    assert manual["metadata"]["fechas"] == ["2026-09-10T12:00:00Z", "2026-10-10T12:00:00Z"]
    assert manual["metadata"]["tipos_mime"] == ["application/pdf"]
    assert manual["metadata"]["categoria"] == "documento"
    assert all(reference.startswith("https://index.commoncrawl.org/") for reference in manual["metadata"]["referencias"])
    sensitive = events["https://api.example.com/backup.sql"]["metadata"]
    assert sensitive["posible_exposicion_por_nombre"] is True and sensitive["evaluable"] is False
    rows = normalized(result)
    assert {row["valor"] for row in rows} == {"api.example.com"}
    assert {row["atributo"] for row in rows} == {"info_host"} and score(rows) == 0

    chunks = report_chunks(result)
    raw = [{"event_type": "RAW_RIR_DATA", "data": json.dumps(chunk), "module": "sfp_baxter_commoncrawl",
            "scan_target": "api.example.com", "source_data": "api.example.com", "false_positive": 0}
           for chunk in chunks]
    rebuilt = reports(raw)
    assert len(rebuilt) == 1 and len(rebuilt[0]["events"]) == 3


def test_commoncrawl_fuga002_sensitive_document_is_informational_and_traceable():
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    row = {"url": "https://files.example.com/hr/internal-payroll.xlsx", "timestamp": "20261118120000",
           "status": "200", "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           "digest": "FIXTURE", "filename": "crawl/fixture.warc.gz", "offset": "10", "length": "20"}
    report = collect("common_crawl", "files.example.com",
                     lambda url, _params: (200, catalog) if url.endswith("collinfo.json") else (200, [row]),
                     commoncrawl_indexes=1)
    event = report["events"][0]
    metadata = event["metadata"]
    assert event["source_data"] == "files.example.com" and event["observed_at"] == "2026-11-18T12:00:00Z"
    assert metadata["documento_indexado"] is True and metadata["tipo_documento"] == "Excel"
    assert metadata["tipos_mime"] == [row["mime"]] and metadata["posible_exposicion_por_nombre"] is True
    assert metadata["posible_documento_sensible"] is True
    assert metadata["issues"][0]["rule"] == "FUGA-002" and metadata["issues"][0]["evaluable"] is False
    assert metadata["reglas_candidatas"] == ["FUGA-002"] and metadata["referencias"]
    rows = normalized(report)
    assert {item["valor"] for item in rows} == {"files.example.com"}
    active = Regla("fuga2", "FUGA-002", "Documentos", "fuga_de_datos", "media", 12, esta_activa=True)
    observations = [Obs(str(i), "asset-files", item["tipo"], item["valor"], item["atributo"], item["datos"], "SpiderFoot", "sf")
                    for i, item in enumerate(rows)]
    assert "FUGA-002" not in DEFINICIONES
    assert evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW).hallazgos == []


def test_commoncrawl_fuga002_normal_document_and_query_name_are_not_sensitive():
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    rows = [
        {"url": "https://files.example.com/public/manual.pdf", "timestamp": "20261118120000", "status": "200", "mime": "application/pdf"},
        {"url": "https://files.example.com/public/guide.docx?secret=public", "timestamp": "20261118120100", "status": "200",
         "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ]
    report = collect("common_crawl", "files.example.com",
                     lambda url, _params: (200, catalog) if url.endswith("collinfo.json") else (200, rows),
                     commoncrawl_indexes=1)
    for event in report["events"]:
        metadata = event["metadata"]
        assert metadata["documento_indexado"] is True
        assert metadata["posible_exposicion_por_nombre"] is False
        assert metadata["posible_documento_sensible"] is False
        assert metadata["issues"] == [] and metadata["reglas_candidatas"] == []


def test_commoncrawl_discards_other_hosts_and_preserves_partial_failures():
    catalog = [
        {"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"},
        {"id": "CC-MAIN-2026-39", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-39-index"},
    ]
    def fetch(url, _params):
        if url.endswith("collinfo.json"):
            return 200, catalog
        if "2026-43" in url:
            return 503, None
        return 200, [{"url": "https://child.api.example.com/private", "timestamp": "20260910120000", "status": "200"}]
    result = collect("common_crawl", "api.example.com", fetch)
    assert result["status"] == "partial" and result["results"] == 0 and result["events"] == []
    assert "otros hostnames" in result["error"] and "no pudieron consultarse" in result["error"]


def test_commoncrawl_recognized_no_captures_404_is_valid_empty():
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    result = collect("common_crawl", "api.example.com",
                     lambda url, _params: (200, catalog) if url.endswith("collinfo.json") else (404, []),
                     commoncrawl_indexes=1)
    assert result["status"] == "empty" and result["results"] == 0
    assert result["queries"][0]["status"] == "empty"


def test_commoncrawl_retries_one_transient_gateway_error_then_recovers():
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    index_calls = 0

    def fetch(url, _params):
        nonlocal index_calls
        if url.endswith("collinfo.json"):
            return 200, catalog
        index_calls += 1
        return (504, None) if index_calls == 1 else (404, [])

    with patch("app.spiderfoot_passive.time.sleep") as retry_sleep:
        result = collect("common_crawl", "api.example.com", fetch, commoncrawl_indexes=1)
    assert result["status"] == "empty" and result.get("error") is None
    assert result["queries"][0]["attempts"] == 2
    assert result["queries"][0]["http_status"] == 404
    assert index_calls == 2
    retry_sleep.assert_called_once_with(0.5)


def test_commoncrawl_queries_two_indexes_concurrently_with_exact_host():
    catalog = [
        {"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"},
        {"id": "CC-MAIN-2026-39", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-39-index"},
    ]
    barrier = threading.Barrier(2)

    def fetch(url, params):
        if url.endswith("collinfo.json"):
            return 200, catalog
        assert params["url"] == "api.example.com" and params["matchType"] == "host"
        barrier.wait(timeout=1)
        return 404, []

    result = collect("common_crawl", "api.example.com", fetch)
    assert result["status"] == "empty" and result["max_concurrency"] == 2
    assert len(result["queries"]) == 2


def test_commoncrawl_retries_timeout_once_then_recovers():
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    attempts = 0

    def fetch(url, _params):
        nonlocal attempts
        if url.endswith("collinfo.json"):
            return 200, catalog
        attempts += 1
        if attempts == 1:
            raise TimeoutError("fixture timeout")
        return 404, []

    result = collect("common_crawl", "api.example.com", fetch,
                     commoncrawl_indexes=1, commoncrawl_retry_delay_seconds=0)
    assert result["status"] == "empty" and attempts == 2
    assert result["queries"][0]["attempts"] == 2


def test_commoncrawl_global_deadline_preserves_other_index_as_partial():
    catalog = [
        {"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"},
        {"id": "CC-MAIN-2026-39", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-39-index"},
    ]
    release = threading.Event()

    def fetch(url, _params):
        if url.endswith("collinfo.json"):
            return 200, catalog
        if "2026-39" in url:
            return 404, []
        release.wait(timeout=1)
        return 504, None

    started = time.monotonic()
    result = collect("common_crawl", "api.example.com", fetch,
                     commoncrawl_deadline_seconds=0.05, commoncrawl_retry_delay_seconds=0)
    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 0.5
    assert result["status"] == "partial" and "1 índices" in result["error"]
    assert {query["status"] for query in result["queries"]} == {"empty", "error"}


def test_rdap_subdomain_uses_registrable_domain_and_never_scores():
    bootstrap = {"services": [["invalid"], [["uk"], ["https://rdap.registry.example/uk/"]]]}
    domain = {
        "objectClassName": "domain", "ldhName": "EXAMPLE.CO.UK",
        "status": ["active", "client transfer prohibited", "active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-02T03:04:05Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-11-19T10:00:00Z"},
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "ns1.example.net"}, {"ldhName": "ns2.example.net"}],
        "entities": [{"roles": ["registrar"], "handle": "999",
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Fixture Registrar"]]],
                      "publicIds": [{"type": "IANA Registrar ID", "identifier": "999"}],
                      "links": [{"href": "https://registrar.example/", "rel": "about"}]}],
        "links": [{"href": "https://rdap.registry.example/uk/domain/example.co.uk", "rel": "self", "type": "application/rdap+json"}],
    }
    calls = []
    def fetch(url, params):
        calls.append((url, params))
        return (200, bootstrap) if url.endswith("dns.json") else (200, domain)
    result = collect("rdap", "api.example.co.uk", fetch, registrable_domain="example.co.uk")
    assert result["status"] == "ok" and result["registrable_domain"] == "example.co.uk"
    assert result["is_subdomain"] is True and len(calls) == 2
    assert calls[1][0] == "https://rdap.registry.example/uk/domain/example.co.uk"
    assert result["nameservers"] == ["ns1.example.net", "ns2.example.net"]
    assert result["registrar"]["name"] == "Fixture Registrar"
    event = result["events"][0]
    assert event["source_data"] == "api.example.co.uk"
    assert event["metadata"]["dominio_registrable"] == "example.co.uk"
    assert event["metadata"]["propiedad_atribuida"] is False and event["metadata"]["evaluable"] is False
    rows = adaptar("SpiderFoot", [export(result)], "example.co.uk")["observaciones"]
    assert {row["valor"] for row in rows} == {"api.example.co.uk"}
    assert {row["atributo"] for row in rows} == {"info_host"} and score(rows) == 0
    rebuilt = reports([export(chunk) for chunk in report_chunks(result)])
    assert len(rebuilt) == 1 and rebuilt[0]["registrar"]["name"] == "Fixture Registrar"


def test_rdap_absence_rate_limit_and_partial_fields_are_distinct():
    bootstrap = {"services": [["invalid"], [["com"], ["https://rdap.registry.example/"]]]}
    def outcome(code, body):
        return collect("rdap", "example.com",
                       lambda url, _params: (200, bootstrap) if url.endswith("dns.json") else (code, body),
                       registrable_domain="example.com")
    empty = outcome(404, {"errorCode": 404})
    limited = outcome(429, {"errorCode": 429})
    partial = outcome(200, {"objectClassName": "domain", "ldhName": "example.com"})
    assert empty["status"] == "empty" and empty["registration_state"] == "absent"
    assert limited["status"] == "error" and limited["rate_limited"] is True and limited["events"] == []
    assert partial["status"] == "partial" and partial["events"]
    assert set(partial["field_states"].values()) == {"ausente_en_respuesta"}


def test_dns_doh_exact_records_interpretation_and_normalization():
    records = {
        ("example.com", "MX"): [(15, "10 mail.provider.net.")],
        ("example.com", "TXT"): [(16, '"v=spf1 +all"'), (16, '"provider-verification=fixture"')],
        ("example.com", "CNAME"): [(5, "alias.provider.net."), (1, "203.0.113.99")],
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=none; pct=50"')],
        ("example.com", "NS"): [(2, "ns.provider.net.")],
    }
    result = collect("google_dns_doh", "example.com", dns_fetch(records, ad=True))
    checks = {check["check"]: check for check in result["checks"]}
    assert result["status"] == "ok"
    assert checks["spf"]["state"] == "present"
    assert {issue["code"] for issue in checks["spf"]["issues"]} == {"SPF_ALLOW_ALL"}
    assert {issue["code"] for issue in checks["dmarc"]["issues"]} == {"DMARC_MONITOR_ONLY", "DMARC_PARTIAL_PERCENTAGE"}
    assert checks["dkim"]["state"] == "unverified"
    assert checks["dnssec"]["state"] == "present"
    assert checks["cname"]["records"] == [{"name": "example.com", "type": "CNAME", "ttl": 300, "data": "alias.provider.net."}]
    rows = normalized(result)
    assert rows and {row["valor"] for row in rows} == {"example.com"}
    assert all(row["atributo"] == "info_host" and row["datos"]["tipo_evento"] == "DNS_POSTURE" for row in rows)
    assert not any(row["valor"] in {"mail.provider.net", "alias.provider.net", "ns.provider.net"} for row in rows)


def test_dns_doh_distinguishes_absence_failure_and_unverified_states():
    empty = collect("google_dns_doh", "example.com", dns_fetch())
    checks = {check["check"]: check for check in empty["checks"]}
    assert empty["status"] == "ok" and checks["mx"]["state"] == "absent"
    assert checks["dmarc"]["state"] == "unverified" and checks["dkim"]["state"] == "unverified"
    assert checks["spf"]["issues"] == [] and checks["dnssec"]["state"] == "unverified"

    partial = collect("google_dns_doh", "example.com", dns_fetch(failures={("example.com", "A")}))
    assert partial["status"] == "partial"
    assert next(check for check in partial["checks"] if check["check"] == "a")["state"] == "error"

    all_failed = {("example.com" if prefix == "target" else f"{prefix}.example.com", rrtype)
                  for _check, rrtype, prefix in DNS_QUERIES}
    failed = collect("google_dns_doh", "example.com", dns_fetch(failures=all_failed))
    assert failed["status"] == "error" and "no fue evaluado" in failed["error"]


def test_dns_doh_stops_after_two_consecutive_transport_failures():
    fetch = Mock(side_effect=TimeoutError("fixture timeout"))
    failed = collect("google_dns_doh", "example.com", fetch)
    assert failed["status"] == "error"
    assert fetch.call_count == 2
    checks = [check for check in failed["checks"] if check["check"] not in {"spf", "dnssec", "dkim"}]
    assert sum(check.get("error_type") == "provider_circuit_open" for check in checks) == len(DNS_QUERIES) - 2
    assert "TimeoutError" in failed["error"]


def test_dns_doh_infra004_dangling_cname_is_informational_and_exactly_attributed():
    records = {("api.example.com", "CNAME"): [(5, "orphan.vendor.example.")]}
    statuses = {("orphan.vendor.example", "A"): 3, ("orphan.vendor.example", "AAAA"): 3}
    report = collect("google_dns_doh", "api.example.com", dns_fetch(records, statuses=statuses))
    cname = next(check for check in report["checks"] if check["check"] == "cname")
    assessment = cname["cname_target_assessment"]
    assert assessment["state"] == "nxdomain" and assessment["claimability_verified"] is False
    assert assessment["attributed_to_customer"] is False and len(assessment["queries"]) == 2
    issue = cname["issues"][0]
    assert issue["code"] == "DANGLING_CNAME_NXDOMAIN" and issue["rule"] == "INFRA-004"
    assert issue["evaluable"] is False and "INFRA-004" not in DEFINICIONES
    rows = normalized(report)
    assert rows and {row["valor"] for row in rows} == {"api.example.com"}
    assert not any(row["valor"] == "orphan.vendor.example" for row in rows)
    active = Regla("infra4", "INFRA-004", "Takeover", "infraestructura", "alta", 20, esta_activa=True)
    observations = [Obs(str(i), "asset-api", row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf")
                    for i, row in enumerate(rows)]
    assert evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW).hallazgos == []


def test_dns_doh_infra004_resolvable_cname_is_negative():
    records = {
        ("api.example.com", "CNAME"): [(5, "live.vendor.example.")],
        ("live.vendor.example", "A"): [(1, "192.0.2.25")],
    }
    report = collect("google_dns_doh", "api.example.com", dns_fetch(records))
    cname = next(check for check in report["checks"] if check["check"] == "cname")
    assert cname["cname_target_assessment"]["state"] == "resolvable"
    assert not any(issue.get("rule") == "INFRA-004" for issue in cname["issues"])


def test_dns_doh_infra004_incomplete_or_ambiguous_evidence_never_flags():
    records = {("api.example.com", "CNAME"): [(5, "unknown.vendor.example.")]}
    report = collect("google_dns_doh", "api.example.com",
                     dns_fetch(records, failures={("unknown.vendor.example", "A")},
                               statuses={("unknown.vendor.example", "AAAA"): 3}))
    cname = next(check for check in report["checks"] if check["check"] == "cname")
    assert cname["cname_target_assessment"]["state"] == "unverified"
    assert not any(issue.get("rule") == "INFRA-004" for issue in cname["issues"])


def test_dns_doh_prepares_conf_003_without_changing_rule_activation_or_weight():
    records = {
        ("example.com", "MX"): [(15, "10 mail.example.net.")],
        ("example.com", "TXT"): [(16, '"v=spf1 ~all"')],
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=none"')],
    }
    rows = normalized(collect("google_dns_doh", "example.com", dns_fetch(records)))
    observations = [Obs(str(i), "asset", row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf") for i, row in enumerate(rows)]
    inactive = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=False)
    active = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=True)
    disabled_result = evaluar_riesgo(observations, [inactive], {"SpiderFoot": "completado"}, NOW)
    enabled_result = evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW)
    assert disabled_result.puntaje.puntaje_global == 0
    assert [finding.regla_codigo for finding in disabled_result.hallazgos] == ["CONF-003"]
    assert disabled_result.hallazgos[0].nivel_evidencia == "potencial"
    assert [finding.regla_codigo for finding in enabled_result.hallazgos] == ["CONF-003"]
    assert enabled_result.puntaje.puntaje_global > 0
    finding = enabled_result.hallazgos[0]
    assert {issue["code"] for issue in finding.evidencia["detalle"]["problemas_dns"]} == {"DMARC_MONITOR_ONLY", "SPF_SOFTFAIL_ALL"}
    assert finding.activo_id == "asset" and finding.severidad == "media"
    assert finding.evidencia["peso"] == 10 and finding.evidencia["aporte"] == 9.4


def test_dns_doh_conf003_secure_no_mail_and_insufficient_evidence_are_negative():
    secure = {
        ("example.com", "MX"): [(15, "10 mail.example.net.")],
        ("example.com", "TXT"): [(16, '"v=spf1 include:_spf.example.net -all"')],
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=reject; pct=100"')],
    }
    active = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=True)
    rows = normalized(collect("google_dns_doh", "example.com", dns_fetch(secure)))
    empty_rows = normalized(collect("google_dns_doh", "nomail.example.com", dns_fetch()))
    observations = [Obs(str(i), row["valor"], row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf")
                    for i, row in enumerate(rows + empty_rows)]
    result = evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW)
    assert result.hallazgos == [] and result.puntaje.puntaje_global == 0


def test_dns_doh_spf_softfail_without_mail_context_is_informational():
    report = collect("google_dns_doh", "example.com", dns_fetch({
        ("example.com", "TXT"): [(16, '"v=spf1 ~all"')],
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=reject"')],
    }))
    spf = next(check for check in report["checks"] if check["check"] == "spf")
    assert spf["mail_enabled"] is False
    assert spf["issues"][0]["code"] == "SPF_SOFTFAIL_ALL"
    assert spf["issues"][0]["evaluable"] is False
    rows = normalized(report)
    observations = [Obs(str(i), "asset", row["tipo"], row["valor"], row["atributo"], row["datos"], "SpiderFoot", "sf")
                    for i, row in enumerate(rows)]
    active = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=True)
    result = evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW)
    assert result.hallazgos == [] and result.puntaje.puntaje_global == 0


@pytest.mark.parametrize("pct", ["-1", "101", "invalid"])
def test_dns_doh_conf003_rejects_invalid_dmarc_percentage(pct):
    records = {("_dmarc.example.com", "TXT"): [(16, f'"v=DMARC1; p=reject; pct={pct}"')]}
    report = collect("google_dns_doh", "example.com", dns_fetch(records))
    dmarc = next(check for check in report["checks"] if check["check"] == "dmarc")
    assert {issue["code"] for issue in dmarc["issues"]} == {"DMARC_PCT_INVALID"}


@pytest.mark.parametrize("third_party_answer", [False, True])
def test_dns_doh_conf003_inherits_only_authorized_root_dmarc_policy(third_party_answer):
    root = collect("google_dns_doh", "example.com", dns_fetch({
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=reject; sp=none; pct=100"')],
    }))
    base = dns_fetch()
    def child_fetch(url, params):
        code, data = base(url, params)
        if params["name"] == "_dmarc.api.example.com":
            if third_party_answer:
                data["Answer"] = [{"name": "_dmarc.provider.net.", "type": 16, "TTL": 300,
                                   "data": '"v=DMARC1; p=none"'}]
            else:
                data["Status"] = 3
        return code, data
    child = collect("google_dns_doh", "api.example.com", child_fetch)
    rows = normalized(root) + normalized(child)
    observations = [Obs(str(i), "root" if row["tipo"] == "dominio" else "child", row["tipo"], row["valor"],
                        row["atributo"], row["datos"], "SpiderFoot", "sf") for i, row in enumerate(rows)]
    active = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=True)
    result = evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW)
    assert not any(row["valor"] == "provider.net" for row in rows)
    if third_party_answer:
        assert result.hallazgos == []
        return
    assert len(result.hallazgos) == 1 and result.hallazgos[0].activo_id == "child"
    detail = result.hallazgos[0].evidencia["detalle"]
    assert detail["dmarc_heredada_desde"] == "example.com"
    assert {issue["code"] for issue in detail["problemas_dns"]} == {"DMARC_INHERITED_MONITOR_ONLY"}


def test_dns_doh_conf003_exact_subdomain_policy_overrides_inheritance():
    root = collect("google_dns_doh", "example.com", dns_fetch({
        ("_dmarc.example.com", "TXT"): [(16, '"v=DMARC1; p=none"')],
    }))
    child = collect("google_dns_doh", "api.example.com", dns_fetch({
        ("_dmarc.api.example.com", "TXT"): [(16, '"v=DMARC1; p=reject; pct=100"')],
    }))
    rows = normalized(root) + normalized(child)
    observations = [Obs(str(i), "root" if row["tipo"] == "dominio" else "child", row["tipo"], row["valor"],
                        row["atributo"], row["datos"], "SpiderFoot", "sf") for i, row in enumerate(rows)]
    active = Regla("conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=True)
    result = evaluar_riesgo(observations, [active], {"SpiderFoot": "completado"}, NOW)
    assert {finding.activo_id for finding in result.hallazgos} == {"root"}


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "::1"])
def test_private_ip_denied(target):
    with pytest.raises(ValueError):
        selected_modules(target)


def test_profile_rejects_active_modules_and_migrates_legacy_preset():
    with pytest.raises(ValueError):
        selected_modules("example.com", "sfp_spider,sfp_active_unknown")
    assert selected_modules("example.com", LEGACY_MODULES) == [
        "sfp_dnsresolve", "sfp_dnsraw", "sfp_robtex", "sfp_crobat_api",
        "sfp_baxter_dns_doh", "sfp_baxter_urlscan", "sfp_baxter_rdap",
    ]
    assert "sfp_baxter_commoncrawl" not in selected_modules(
        "example.com", COMMONCRAWL_RDAP_DEFAULT_MODULES,
    )
    assert selected_modules("example.com", "sfp_baxter_commoncrawl") == [
        "sfp_baxter_commoncrawl",
    ]
    assert selected_modules(
        "example.com", "sfp_baxter_urlscan,sfp_baxter_commoncrawl,sfp_baxter_rdap",
    ) == ["sfp_baxter_urlscan", "sfp_baxter_rdap"]
    with pytest.raises(ValueError):
        selected_modules(IP)
    with pytest.raises(ValueError):
        selected_modules(IP, "sfp_baxter_internetdb")


def test_false_positive_and_wrong_target_envelopes_not_ingested():
    result = collect("urlscan", "example.com", lambda *_: (200, {"results": []}))
    for extra in ({"false_positive": 1}, {"scan_target": "9.9.9.9"}):
        raw = [export(result, **extra)]
        assert reports(raw) == []
        assert adaptar("SpiderFoot", raw, "example.com")["observaciones"] == []




def test_inventory_multiasset_scope_budget_and_coverage():
    called = []
    async def runner(target):
        called.append(target)
        report = collect("urlscan", target, lambda *_: (200, {"results": []}))
        return orchestrators.RunnerOutput([export(report)])
    outcome = asyncio.run(orchestrators.run_all("example.com", orchestrators.OrchestratorSettings(),
        runners={"SpiderFoot": runner}, targets=["example.com", "api.example.com", IP, "9.9.9.9", "other.net"],
        max_targets=2, ip_scope="example.com,8.8.8.8"))
    assert called == ["example.com", "api.example.com"]
    assets = [{"id": str(i), "tipo": kind, "valor": value} for i, (kind, value) in enumerate([
        ("dominio", "example.com"), ("subdominio", "api.example.com"), ("ip", IP),
        ("servicio", IP+":22/tcp"), ("ip", "9.9.9.9"), ("correo", "a@example.com")])]
    coverage = build_coverage(assets, outcome, "example.com,8.8.8.8", called)
    assert all(row["consultado"] for row in coverage["activos"][:2])
    assert not any(row["consultado"] for row in coverage["activos"][2:4])
    assert not coverage["activos"][4]["consultado"]
    assert len(coverage["fuentes"]["SpiderFoot"]["modulos"]) == 2
    assert all("response" not in row for row in coverage["fuentes"]["SpiderFoot"]["modulos"])


@pytest.mark.parametrize("provider,target,options,body", [
    ("urlscan", "example.com", {"api_key": "fixture-urlscan"}, {"results": []})])
def test_plugin_exact_target_no_recursive_expansion(provider, target, options, body):
    event_class = lambda event_type, data, module, source: types.SimpleNamespace(eventType=event_type, data=data, module=module)
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    name = "sfp_baxter_"+provider
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": types.SimpleNamespace(get=Mock()), "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin = getattr(module, name)()
        plugin.__name__ = name
        plugin.setup(None, options)
        plugin.getTarget = lambda: types.SimpleNamespace(targetValue=target)
        emitted = []
        plugin.notifyListeners = emitted.append
        with patch.object(module.requests, "get", return_value=types.SimpleNamespace(status_code=200, json=lambda: body)) as get:
            plugin.handleEvent(types.SimpleNamespace(data="neighbor.example.net"))
            get.assert_not_called()
            plugin.handleEvent(types.SimpleNamespace(data=target))
            plugin.handleEvent(types.SimpleNamespace(data=target))
            get.assert_called_once()
            assert get.call_args.kwargs["allow_redirects"] is (provider == "urlscan")
            assert get.call_args.kwargs["timeout"] == 30
            if provider == "urlscan":
                assert get.call_args.kwargs["headers"]["API-Key"] == "fixture-urlscan"
                assert get.call_args.kwargs["verify"] is True
        raw = [{"event_type": event.eventType, "data": event.data, "module": name,
                "scan_target": target, "source_data": target, "false_positive": 0}
               for event in emitted]
        rebuilt = reports(raw)
        assert len(rebuilt) == 1 and rebuilt[0]["status"] in {"empty", "ok"}
        assert all("fixture-urlscan" not in event.data for event in emitted)


def test_commoncrawl_plugin_queries_only_public_indexes_for_exact_target():
    event_class = lambda event_type, data, module, source: types.SimpleNamespace(eventType=event_type, data=data, module=module)
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    name = "sfp_baxter_commoncrawl"
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    catalog = [{"id": "CC-MAIN-2026-43", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index"}]
    responses = [
        types.SimpleNamespace(status_code=200, json=lambda: catalog, text=json.dumps(catalog)),
        types.SimpleNamespace(status_code=404, json=lambda: None, text="No Captures found for: api.example.com"),
    ]
    requests_stub = types.SimpleNamespace(get=Mock(side_effect=responses))
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": requests_stub,
                                  "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin = getattr(module, name)()
        plugin.__name__ = name
        plugin.setup(None, {"indexes": "1", "max_results": "5"})
        plugin.getTarget = lambda: types.SimpleNamespace(targetValue="api.example.com")
        emitted = []
        plugin.notifyListeners = emitted.append
        with patch.object(module.time, "sleep"):
            plugin.handleEvent(types.SimpleNamespace(data="neighbor.example.net"))
            plugin.handleEvent(types.SimpleNamespace(data="api.example.com"))
            plugin.handleEvent(types.SimpleNamespace(data="api.example.com"))
        assert requests_stub.get.call_count == 2
        assert all(call.args[0].startswith("https://index.commoncrawl.org/") for call in requests_stub.get.call_args_list)
        assert requests_stub.get.call_args_list[1].kwargs["params"]["matchType"] == "host"
        assert requests_stub.get.call_args_list[1].kwargs["params"]["url"] == "api.example.com"
        assert requests_stub.get.call_args_list[1].kwargs["timeout"] == (5, 20)
        raw = [{"event_type": event.eventType, "data": event.data, "module": name,
                "scan_target": "api.example.com", "source_data": "api.example.com", "false_positive": 0}
               for event in emitted]
        rebuilt = reports(raw)
        assert len(rebuilt) == 1 and rebuilt[0]["status"] == "empty"
        assert max(len(event.data) for event in emitted) <= 900


def test_rdap_plugin_resolves_parent_and_caches_duplicate_registration_queries():
    event_class = lambda event_type, data, module, source: types.SimpleNamespace(eventType=event_type, data=data, module=module)
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    suffix_stub = types.SimpleNamespace(PublicSuffixList=lambda **_kwargs: types.SimpleNamespace(
        privatesuffix=lambda _target: "example.co.uk"))
    name = "sfp_baxter_rdap"
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    bootstrap = {"services": [["invalid"], [["uk"], ["https://rdap.registry.example/uk/"]]]}
    domain = {"objectClassName": "domain", "ldhName": "example.co.uk", "status": ["active"],
              "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                         {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
              "nameservers": [{"ldhName": "ns1.example.net"}],
              "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar"]]]}]}
    responses = [types.SimpleNamespace(status_code=200, json=lambda: bootstrap),
                 types.SimpleNamespace(status_code=200, json=lambda: domain)]
    requests_stub = types.SimpleNamespace(get=Mock(side_effect=responses))
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": requests_stub,
                                  "publicsuffixlist": suffix_stub,
                                  "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module._CACHE.clear()
        emitted = []
        for target in ("api.example.co.uk", "www.example.co.uk"):
            plugin = getattr(module, name)(); plugin.__name__ = name; plugin.setup(None, {})
            plugin.getTarget = lambda value=target: types.SimpleNamespace(targetValue=value)
            plugin.notifyListeners = emitted.append
            plugin.handleEvent(types.SimpleNamespace(data=target))
        assert requests_stub.get.call_count == 2
        assert requests_stub.get.call_args_list[0].args[0] == "https://data.iana.org/rdap/dns.json"
        assert requests_stub.get.call_args_list[1].args[0] == "https://rdap.registry.example/uk/domain/example.co.uk"
        assert all("api.example.co.uk" not in call.args[0] and "www.example.co.uk" not in call.args[0]
                   for call in requests_stub.get.call_args_list)
        assert emitted and all(json.loads(event.data)["provider"] == "rdap" for event in emitted)


def test_urlscan_combines_public_and_institutional_ca(tmp_path):
    event_class = lambda *args: types.SimpleNamespace()
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    requests_stub = types.SimpleNamespace(get=Mock(), certs=types.SimpleNamespace())
    name = "sfp_baxter_urlscan"
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    public_ca, custom_ca = tmp_path/"public.pem", tmp_path/"custom.pem"
    public_ca.write_text("PUBLIC-CA\n", encoding="utf-8")
    custom_ca.write_text("CUSTOM-CA\n", encoding="utf-8")
    requests_stub.certs.where = lambda: str(public_ca)
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": requests_stub,
                                  "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        combined = Path(module._combined_ca_bundle(str(custom_ca)))
        try:
            content = combined.read_text(encoding="utf-8")
            assert "PUBLIC-CA" in content and "CUSTOM-CA" in content
            assert combined != custom_ca
        finally:
            combined.unlink(missing_ok=True)


def test_dns_doh_combines_public_and_institutional_ca(tmp_path):
    event_class = lambda *args: types.SimpleNamespace()
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    requests_stub = types.SimpleNamespace(get=Mock(), certs=types.SimpleNamespace())
    name = "sfp_baxter_dns_doh"
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    public_ca, custom_ca = tmp_path/"public.pem", tmp_path/"custom.pem"
    public_ca.write_text("PUBLIC-CA\n", encoding="utf-8")
    custom_ca.write_text("CUSTOM-CA\n", encoding="utf-8")
    requests_stub.certs.where = lambda: str(public_ca)
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": requests_stub,
                                  "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        combined = Path(module._combined_ca_bundle(str(custom_ca)))
        try:
            content = combined.read_text(encoding="utf-8")
            assert "PUBLIC-CA" in content and "CUSTOM-CA" in content
            assert combined != custom_ca
        finally:
            combined.unlink(missing_ok=True)


def test_dns_doh_plugin_queries_only_the_exact_spiderfoot_target():
    event_class = lambda event_type, data, module, source: types.SimpleNamespace(eventType=event_type, data=data, module=module)
    stub = types.SimpleNamespace(SpiderFootPlugin=type("Plugin", (), {}), SpiderFootEvent=event_class)
    name = "sfp_baxter_dns_doh"
    path = Path(__file__).resolve().parents[2]/"deploy"/"spiderfoot"/"modules"/(name+".py")
    response = types.SimpleNamespace(status_code=200, json=lambda: {"Status": 0, "AD": False, "Answer": []})
    with patch.dict(sys.modules, {"spiderfoot": stub, "requests": types.SimpleNamespace(get=Mock()), "baxter_passive": sys.modules["app.spiderfoot_passive"]}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin = getattr(module, name)()
        plugin.__name__ = name
        plugin.setup(None, {})
        plugin.getTarget = lambda: types.SimpleNamespace(targetValue="api.example.com")
        emitted = []
        plugin.notifyListeners = emitted.append
        with patch.object(module.requests, "get", return_value=response) as get:
            plugin.handleEvent(types.SimpleNamespace(data="neighbor.example.com"))
            get.assert_not_called()
            plugin.handleEvent(types.SimpleNamespace(data="api.example.com"))
            plugin.handleEvent(types.SimpleNamespace(data="api.example.com"))
            assert get.call_count == len(DNS_QUERIES)
            assert all(call.kwargs["allow_redirects"] is False and call.kwargs["timeout"] == (5, 10)
                       and call.kwargs["verify"] is True for call in get.call_args_list)
            assert {call.kwargs["params"]["name"] for call in get.call_args_list} == {
                "api.example.com", "_dmarc.api.example.com", "_mta-sts.api.example.com", "_smtp._tls.api.example.com"
            }
        assert emitted
        assert max(len(event.data) for event in emitted) <= 900
        raw = [{"event_type": event.eventType, "data": event.data, "module": name,
                "scan_target": "api.example.com", "source_data": "api.example.com", "false_positive": 0}
               for event in emitted]
        rebuilt = reports(raw)
        assert len(rebuilt) == 1 and rebuilt[0]["provider"] == "google_dns_doh" and rebuilt[0]["status"] == "ok"
        assert len(rebuilt[0]["checks"]) == 15 and len(rebuilt[0]["events"]) == 15
        incomplete = reports(raw[:-1])
        assert incomplete[0]["status"] == "partial"
        assert "fragmentos" in incomplete[0]["error"] or "14 de 15" in incomplete[0]["error"]


def test_large_provider_report_is_fragmented_below_spiderfoot_limit_and_reassembled():
    report = {
        "profile": "baxter-passive-v1", "provider": "common_crawl", "target": "api.example.com",
        "status": "ok", "query": "https://index.commoncrawl.org/" + "q" * 1500,
        "events": [{"event_type": "COMMONCRAWL_URL", "data": "https://api.example.com/" + "x" * 1200,
                    "source_data": "api.example.com"}],
        "results": 1, "checked_at": "2026-11-20T00:00:00+00:00",
        "limitations": ["Evidencia histórica " + "á" * 500],
    }
    chunks = report_chunks(report)
    assert len(chunks) > 1
    assert max(len(serialize_report_chunk(chunk)) for chunk in chunks) <= 900
    raw = [{"event_type": "RAW_RIR_DATA", "data": serialize_report_chunk(chunk),
            "module": "sfp_baxter_commoncrawl", "scan_target": "api.example.com", "false_positive": 0}
           for chunk in chunks]
    rebuilt = reports(raw)
    assert len(rebuilt) == 1
    assert rebuilt[0]["query"] == report["query"]
    assert rebuilt[0]["events"] == report["events"]


def test_passive_report_serialization_hides_names_from_spiderfoot_and_roundtrips():
    value = {
        "profile": "baxter-passive-v1", "provider": "google_dns_doh",
        "target": "api.example.com", "ratio": 0.5, "events": [],
    }
    encoded = serialize_report_chunk(value)
    assert "api.example.com" not in encoded
    assert "api\\u002eexample\\u002ecom" in encoded
    assert "0.5" in encoded
    assert json.loads(encoded) == value


def test_disabled_commoncrawl_is_explicitly_unavailable_and_not_a_zero_result():
    raw = unavailable_report_event(
        "sfp_baxter_commoncrawl", "api.example.com", "HTTP 504 persistente",
    )
    parsed = reports([raw])
    assert len(parsed) == 1
    assert parsed[0]["status"] == "unavailable"
    assert parsed[0]["disabled"] is True
    assert parsed[0]["results"] == 0 and parsed[0]["events"] == []
    assert "HTTP 504" in parsed[0]["error"]


def test_dns_module_does_not_turn_internal_passive_report_into_assets():
    internal = json.dumps({"profile": "baxter-passive-v1", "provider": "google_dns_doh",
                           "target": "example.com", "status": "error", "events": []})
    result = adaptar("SpiderFoot", [{
        "event_type": "INTERNET_NAME", "data": "dmarc.example.com",
        "source_data": internal, "module": "sfp_dnsresolve",
    }], "example.com")
    assert result["observaciones"] == []
    assert result["descartadas"] == [{
        "motivo": "evento_derivado_reporte_pasivo", "entrada": "INTERNET_NAME",
    }]


def test_dns_doh_chunk_roundtrip_preserves_normalization_and_issues():
    report = collect("google_dns_doh", "example.com", dns_fetch({
        ("example.com", "MX"): [(15, "10 mail.example.net.")],
        ("example.com", "TXT"): [(16, '"v=spf1 +all"')],
    }))
    raw = [{"event_type": "RAW_RIR_DATA", "data": json.dumps(chunk), "module": "sfp_baxter_dns_doh",
            "scan_target": "example.com", "source_data": "example.com", "false_positive": 0}
           for chunk in report_chunks(report)]
    rebuilt = reports(raw)
    assert len(rebuilt) == 1
    rows = adaptar("SpiderFoot", raw, "example.com")["observaciones"]
    assert len(rows) == 15 and {row["valor"] for row in rows} == {"example.com"}
    spf = next(row for row in rows if row["datos"].get("check") == "spf")
    assert spf["datos"]["issues"][0]["code"] == "SPF_ALLOW_ALL"
    coverage = build_coverage(
        [{"id": "asset", "tipo": "dominio", "valor": "example.com"}],
        {"SpiderFoot": {"estado": "completado", "contenido": raw, "consultas": [
            {"objetivo": "example.com", "estado": "completado"}
        ]}},
        "example.com", ["example.com"],
    )
    module = coverage["fuentes"]["SpiderFoot"]["modulos"][0]
    assert len(module["checks"]) == 15 and "events" not in module


def test_failed_source_preserves_raw_provider_errors_for_report():
    from app import scan_service
    from unittest.mock import MagicMock
    raw = [export(collect("urlscan", "example.com", lambda *_: (503, {})))]
    summary = {"resultado_crudo_id": "raw-fixture", "ya_procesado": False, "observaciones_generadas": 0,
               "activos_nuevos": 0, "activos_existentes": 0, "observaciones_nuevas": 0,
               "observaciones_duplicadas": 0, "descartadas": {}}
    with patch.object(scan_service, "ingestar_resultado", return_value=summary) as ingest:
        result = scan_service._persist_source(MagicMock(), "org", "scan", "sf", "SpiderFoot", "example.com",
            {"estado": "fallido", "contenido": raw, "error": "Sin clave"})
    assert ingest.call_args.kwargs["raw"] == raw
    assert result["resultado_crudo_id"] == "raw-fixture"
    assert result["estado"] == "fallido"


def test_failed_additional_target_does_not_discard_provider_report():
    good = export(collect("urlscan", "example.com", lambda *_: (200, {"results": []})))
    bad = export(collect("urlscan", "api.example.com", lambda *_: (429, {})))
    merged = orchestrators._merge_outcomes("SpiderFoot",
        {"estado": "completado", "contenido": [good]},
        {"estado": "fallido", "contenido": [bad], "error": "HTTP 429"})
    assert len(reports(merged["contenido"])) == 2
    assert "429" in merged["error"]


def test_authorized_inventory_over_limit_is_pending_not_evaluated():
    async def runner(target):
        return [export(collect("urlscan", target, lambda *_: (200, {"results": []})))]
    outcome = asyncio.run(orchestrators.run_all("example.com", orchestrators.OrchestratorSettings(),
        runners={"SpiderFoot": runner}, targets=["api.example.com", "dev.example.com"],
        max_targets=1, ip_scope="example.com"))
    assert set(outcome["SpiderFoot"]["objetivos_pendientes"]) == {"api.example.com", "dev.example.com"}
    coverage = build_coverage([{"id": "api", "tipo": "subdominio", "valor": "api.example.com"}], outcome, "example.com", [])
    assert not coverage["activos"][0]["consultado"]
    assert "Límite" in coverage["activos"][0]["motivo"]








def test_spiderfoot_ui_seed_is_not_provider_evidence():
    result = adaptar("SpiderFoot", [{
        "event_type": "INTERNET_NAME", "data": "example.com",
        "module": "SpiderFoot UI", "source_data": "example.com",
    }], "example.com")
    assert result["observaciones"] == []
    assert result["descartadas"] == [{"motivo": "evento_interno_spiderfoot", "entrada": "INTERNET_NAME"}]
