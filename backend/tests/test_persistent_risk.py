"""El riesgo vigente sobrevive a un escaneo sin evidencia nueva hasta su resolución."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from fastapi import HTTPException

from app import main
from app.risk.modelos import Hallazgo, Obs, Regla
from app.risk.motor import evaluar_riesgo, puntuar_hallazgos
from app.risk.persistencia import (
    _actualizar_exposicion, _consolidar_hallazgos, _hallazgo_atribuido, _hallazgos_previos,
    _observaciones_atribuidas, calcular_y_guardar, leer_hallazgos,
)


REGLA = Regla("regla-1", "INFRA-001", "Administración remota", "infraestructura", "alta", 15)
ESTADOS = {"SpiderFoot": "completado", "Shodan": "fallido"}
OBS = Obs("obs-1", "activo-1", "servicio", "203.0.113.10:22/tcp", "servicio_expuesto", {}, "SpiderFoot", "fuente-1")


def _detectado():
    return evaluar_riesgo([OBS], [REGLA], ESTADOS).hallazgos[0]


def _anterior(hallazgo):
    return {
        "activo_id": hallazgo.activo_id,
        "regla_id": hallazgo.regla_id,
        "fuente_id": hallazgo.fuente_id,
        "categoria": hallazgo.categoria,
        "severidad": hallazgo.severidad,
        "confianza": hallazgo.confianza,
        "evidencia": hallazgo.evidencia,
        "estado": "abierto",
    }


def test_hallazgo_repetido_se_cuenta_una_vez():
    detectado = _detectado()
    vigentes, arrastrados = _consolidar_hallazgos(
        [detectado], [_anterior(detectado)], set(), [REGLA], "escaneo-2", "escaneo-1"
    )
    assert len(vigentes) == 1
    assert arrastrados == 0
    assert vigentes[0].evidencia["ultimo_escaneo_con_evidencia"] == "escaneo-2"


def test_hallazgo_potencial_persiste_en_evidencia_sin_puntuar_ni_cambiar_exposicion():
    potential = Hallazgo(
        activo_id="activo-1", regla_id=REGLA.id, regla_codigo=REGLA.codigo,
        fuente_id="fuente-1", categoria=REGLA.categoria, severidad=REGLA.severidad,
        confianza=0.7, evidencia={"regla": REGLA.codigo, "aporte_potencial_estimado": 13.2},
        nivel_evidencia="potencial", antiguedad_dias=12,
        motivo_no_confirmado="Evidencia histórica sin verificación actual.",
    )
    payload = potential.como_dict()
    assert payload["evidencia"]["nivel_evidencia"] == "potencial"
    assert payload["evidencia"]["antiguedad_dias"] == 12
    assert "aporte" not in payload["evidencia"]
    assert puntuar_hallazgos([potential], [REGLA])["puntaje_global"] == 0
    report = {"activos": [{"id": "activo-1", "consultas": [], "evaluado_seguridad": False}]}
    _actualizar_exposicion(report, [potential], [REGLA])
    assert report["activos"][0]["exposicion"] == "Sin evaluar"


def test_hallazgo_historico_sin_clasificacion_no_se_reinterpreta_ni_puntua():
    previous = _anterior(_detectado())
    previous["evidencia"].pop("nivel_evidencia", None)
    current, carried = _consolidar_hallazgos([], [previous], set(), [REGLA], "scan-2", "scan-1")
    assert carried == 1 and current[0].nivel_evidencia == "sin_clasificar"
    assert puntuar_hallazgos(current, [REGLA])["puntaje_global"] == 0
    assert current[0].como_dict()["evidencia"]["nivel_evidencia"] == "sin_clasificar"


def test_estado_aceptado_se_conserva_con_y_sin_evidencia_nueva():
    previo = _anterior(_detectado())
    previo["estado"] = "aceptado"
    actual, arrastrados = _consolidar_hallazgos(
        [_detectado()], [previo], set(), [REGLA], "escaneo-2", "escaneo-1"
    )
    assert arrastrados == 0
    assert actual[0].como_dict()["estado"] == "aceptado"
    assert puntuar_hallazgos(actual, [REGLA])["puntaje_global"] > 0

    persistente, arrastrados = _consolidar_hallazgos(
        [], [previo], set(), [REGLA], "escaneo-3", "escaneo-2"
    )
    assert arrastrados == 1
    assert persistente[0].como_dict()["estado"] == "aceptado"


def test_escaneo_sin_evidencia_nueva_conserva_el_riesgo_abierto():
    anterior = _anterior(_detectado())
    vigentes, arrastrados = _consolidar_hallazgos(
        [], [anterior], set(), [REGLA], "escaneo-2", "escaneo-1"
    )
    assert arrastrados == 1
    assert vigentes[0].evidencia["pendiente_revalidacion"] is True
    assert puntuar_hallazgos(vigentes, [REGLA])["puntaje_global"] > 0


def test_resolver_reduce_el_puntaje_y_evitar_arrastre():
    anterior = _anterior(_detectado())
    clave = (anterior["activo_id"], anterior["regla_id"])
    vigentes, arrastrados = _consolidar_hallazgos(
        [], [anterior], {clave}, [REGLA], "escaneo-2", "escaneo-1"
    )
    assert arrastrados == 0
    assert puntuar_hallazgos(vigentes, [REGLA])["puntaje_global"] == 0


def test_exposicion_usa_severidad_maxima_y_cobertura_independiente():
    high = _detectado()
    critical_rule = Regla("regla-critica", "INFRA-002", "Crítico", "infraestructura", "critica", 30)
    critical = replace(high, regla_id=critical_rule.id, regla_codigo=critical_rule.codigo, severidad="critica")
    report = {"activos": [
        {"id": high.activo_id, "consultas": [{"fuente": "SpiderFoot"}], "evaluado_seguridad": False},
        {"id": "limpio", "consultas": [{"fuente": "SpiderFoot"}], "evaluado_seguridad": True},
        {"id": "sin-evaluar", "consultas": [], "evaluado_seguridad": False},
        {"id": "fuera", "consultas": [], "evaluado_seguridad": False, "clasificacion_exposicion": "fuera_alcance"},
        {"id": "incompatible", "consultas": [], "evaluado_seguridad": False, "clasificacion_exposicion": "sin_compatibilidad"},
        {"id": "historico", "consultas": [], "evaluado_seguridad": False, "clasificacion_exposicion": "historico_sintetico"},
    ]}
    _actualizar_exposicion(report, [high, critical], [REGLA, critical_rule])
    by_id = {row["id"]: row for row in report["activos"]}
    assert by_id[high.activo_id]["exposicion"] == "Crítica"
    assert by_id[high.activo_id]["estado_cobertura"] == "parcial"
    assert by_id["limpio"]["exposicion"] == "Evaluado sin hallazgos"
    assert by_id["sin-evaluar"]["exposicion"] == "Sin evaluar"
    assert by_id["fuera"]["exposicion"] == "Fuera de alcance"
    assert by_id["fuera"]["estado_cobertura"] == "fuera_alcance"
    assert by_id["incompatible"]["exposicion"] == "Sin evaluación compatible"
    assert by_id["historico"]["exposicion"] == "Histórico/sintético"

    _actualizar_exposicion(report, [], [REGLA, critical_rule])
    assert by_id[high.activo_id]["exposicion"] == "Sin evaluar"
    assert by_id[high.activo_id]["hallazgos_vigentes"] == 0


def test_regla_desactivada_no_permanece_en_el_riesgo():
    anterior = _anterior(_detectado())
    inactiva = Regla(REGLA.id, REGLA.codigo, REGLA.nombre, REGLA.categoria, REGLA.severidad, REGLA.peso, False)
    vigentes, _ = _consolidar_hallazgos([], [anterior], set(), [inactiva], "escaneo-2", "escaneo-1")
    assert vigentes == []


def test_hallazgo_retirado_se_conserva_para_auditoria_sin_arrastrar_riesgo():
    anterior = _anterior(_detectado())
    anterior["estado"] = "aceptado"
    anterior["evidencia"] = {**anterior["evidencia"], "retirado_del_riesgo": True}
    vigentes, arrastrados = _consolidar_hallazgos(
        [], [anterior], set(), [REGLA], "escaneo-2", "escaneo-1"
    )
    assert vigentes == []
    assert arrastrados == 0
    with patch("app.risk.persistencia._paginar", return_value=[
        {"id": "retirado", "severidad": "alta", "confianza": 0.7, "evidencia": anterior["evidencia"]},
        {"id": "vigente", "severidad": "alta", "confianza": 0.7, "evidencia": {}},
    ]):
        assert [row["id"] for row in leer_hallazgos(MagicMock(), "escaneo-1")] == ["vigente"]


def test_servicio_de_ip_compartida_no_aumenta_el_riesgo():
    observaciones, excluidas = _observaciones_atribuidas([OBS], "example.com")
    assert observaciones == []
    assert excluidas == 1
    observaciones, excluidas = _observaciones_atribuidas([OBS], "example.com, 203.0.113.0/24")
    assert observaciones == [OBS]
    assert excluidas == 0
    assert not _hallazgo_atribuido(_anterior(_detectado()), "example.com")
    assert _hallazgo_atribuido(_anterior(_detectado()), "203.0.113.10")


def test_cve_de_ip_autorizada_aporta_riesgo_y_de_ip_compartida_no():
    observation = Obs(
        "obs-cve", "asset-ip", "ip", "8.8.8.8", "cve",
        {"cve": "CVE-2024-12345", "verificado": True}, "Shodan", "source-shodan",
    )
    rule = Regla("rule-cve", "INFRA-003", "CVE reportada", "infraestructura", "media", 8)
    allowed, _ = _observaciones_atribuidas([observation], "example.com, 8.8.8.8")
    findings = evaluar_riesgo(allowed, [rule], {"Shodan": "completado"}).hallazgos
    assert len(findings) == 1
    assert puntuar_hallazgos(findings, [rule])["puntaje_global"] > 0
    assert _hallazgo_atribuido(_anterior(findings[0]), "example.com, 8.8.8.8")
    blocked, excluded = _observaciones_atribuidas([observation], "example.com")
    assert blocked == []
    assert excluded == 1
    assert not _hallazgo_atribuido(_anterior(findings[0]), "example.com")


def test_cve_de_dos_subdominios_autorizados_se_puntua_y_persiste():
    observations = [
        Obs(f"obs-{name}", f"asset-{name}", "subdominio", f"{name}.example.com", "cve",
            {"cve": "CVE-2024-12345", "verificado": True}, "SpiderFoot", "source-spiderfoot")
        for name in ("api", "shop")
    ]
    rule = Regla("rule-cve", "INFRA-003", "CVE reportada", "infraestructura", "media", 8)
    allowed, excluded = _observaciones_atribuidas(observations, "example.com")
    findings = evaluar_riesgo(allowed, [rule], {"SpiderFoot": "completado", "theHarvester": "fallido"}).hallazgos
    assert excluded == 0
    assert {h.activo_id for h in findings} == {"asset-api", "asset-shop"}
    assert all(_hallazgo_atribuido(_anterior(h), "example.com") for h in findings)
    assert puntuar_hallazgos(findings + findings, [rule])["puntaje_global"] == puntuar_hallazgos(findings, [rule])["puntaje_global"]
    assert puntuar_hallazgos(findings, [rule])["puntaje_global"] > 0
    carried, count = _consolidar_hallazgos([], [_anterior(h) for h in findings], set(), [rule], "scan-2", "scan-1")
    assert count == 2
    assert puntuar_hallazgos(carried, [rule])["puntaje_global"] > 0
    blocked, excluded = _observaciones_atribuidas(observations, "other.example.org")
    assert blocked == [] and excluded == 2


def test_calculo_guarda_el_puntaje_persistente_y_su_procedencia():
    client = MagicMock()
    anterior = _anterior(_detectado())
    with (
        patch("app.risk.persistencia.cargar_observaciones", return_value=[]),
        patch("app.risk.persistencia.leer_riesgo", return_value=None),
        patch("app.risk.persistencia.cargar_reglas", return_value=[REGLA]),
        patch("app.risk.persistencia.cargar_estado_fuentes", return_value=ESTADOS),
        patch("app.risk.persistencia._alcance_escaneo", return_value="203.0.113.10"),
        patch("app.risk.persistencia._hallazgos_previos", return_value=("escaneo-1", [anterior])),
        patch("app.risk.persistencia._resueltos_en_escaneo", return_value=set()),
    ):
        resultado = calcular_y_guardar(client, "escaneo-2")
    assert resultado.puntaje.puntaje_global > 0
    assert resultado.puntaje.cobertura["hallazgos_arrastrados"] == 1
    payload = client.rpc.call_args.args[1]
    assert payload["p_puntaje"]["puntaje_global"] == resultado.puntaje.puntaje_global
    assert payload["p_puntaje"]["cobertura"]["riesgo_potencial"]["puntaje_global"] == 0
    global_estimado = payload["p_puntaje"]["cobertura"]["riesgo_global_estimado"]
    assert global_estimado["puntaje_global"] == global_estimado["confirmado"] > 0
    assert payload["p_puntaje"]["cobertura"]["riesgo_confirmado"]["puntaje_global"] == global_estimado["confirmado"]
    assert isinstance(payload["p_puntaje"]["puntaje_global"], int)
    assert payload["p_hallazgos"][0]["evidencia"]["pendiente_revalidacion"] is True


def test_tls_potencial_subunitario_se_persiste_sin_subir_confirmado():
    client = MagicMock()
    tls = Obs("tls-1", "api", "subdominio", "api.example.com", "info_host", {
        "tipo_evento": "URLSCAN_TLS_CERTIFICATE", "historico": True,
        "verificado_actual": False, "evidencia_completa": True, "evaluable": True,
        "valido_desde": "2026-10-01T00:00:00Z", "valido_hasta": "2026-11-25T00:00:00Z",
        "issues": [{"code": "TLS_CERTIFICATE_EXPIRING_HISTORICAL", "rule": "CONF-007", "evaluable": True}],
    }, "SpiderFoot", "sf", "2026-11-18T12:00:00Z")
    rule = Regla("tls-rule", "CONF-007", "TLS próximo", "configuracion", "baja", 1, False)
    with (
        patch("app.risk.persistencia.cargar_observaciones", return_value=[tls]),
        patch("app.risk.persistencia.leer_riesgo", return_value=None),
        patch("app.risk.persistencia.cargar_reglas", return_value=[rule]),
        patch("app.risk.persistencia.cargar_estado_fuentes", return_value=ESTADOS),
        patch("app.risk.persistencia._alcance_escaneo", return_value="example.com"),
        patch("app.risk.persistencia._hallazgos_previos", return_value=(None, [])),
        patch("app.risk.persistencia._resueltos_en_escaneo", return_value=set()),
    ):
        calcular_y_guardar(client, "scan", datetime(2026, 11, 20, tzinfo=timezone.utc))
    rpc, payload = client.rpc.call_args.args
    assert rpc == "guardar_riesgo"
    assert [h["evidencia"]["nivel_evidencia"] for h in payload["p_hallazgos"]] == ["potencial"]
    coverage = payload["p_puntaje"]["cobertura"]
    potential = coverage["riesgo_potencial"]["puntaje_global"]
    assert coverage["riesgo_confirmado"]["puntaje_global"] == 0
    assert 0 < potential < 1
    assert coverage["riesgo_global_estimado"]["puntaje_global"] == potential * 0.5


def test_no_importa_hallazgos_de_escaneos_anteriores_a_la_linea_base():
    client = MagicMock()
    scans = MagicMock()
    risks = MagicMock()
    for query in (scans, risks):
        for method in ("select", "eq", "lt", "order", "range", "in_", "single"):
            getattr(query, method).return_value = query
    scans.execute.side_effect = [
        SimpleNamespace(data={"organizacion_id": "org-1", "finalizado_en": "2026-11-12T12:00:00Z"}),
        SimpleNamespace(data=[{"id": "escaneo-demo"}]),
    ]
    risks.execute.return_value = SimpleNamespace(data=[
        {"escaneo_id": "escaneo-demo", "cobertura": {"evaluadas": ["INFRA-001"]}}
    ])
    client.table.side_effect = lambda name: {"escaneos": scans, "puntajes_riesgo": risks}[name]
    assert _hallazgos_previos(client, "escaneo-actual") == (None, [])


def test_recalcular_un_escaneo_historico_no_lo_convierte_en_linea_base():
    client = MagicMock()
    with (
        patch("app.risk.persistencia.leer_riesgo", return_value={"cobertura": {}, "version_motor": "1.0.0"}),
        patch("app.risk.persistencia.cargar_observaciones", return_value=[]),
        patch("app.risk.persistencia.cargar_reglas", return_value=[REGLA]),
        patch("app.risk.persistencia.cargar_estado_fuentes", return_value=ESTADOS),
        patch("app.risk.persistencia._alcance_escaneo", return_value="203.0.113.10"),
        patch("app.risk.persistencia._hallazgos_previos") as previous,
        patch("app.risk.persistencia._resueltos_en_escaneo", return_value=set()),
    ):
        result = calcular_y_guardar(client, "escaneo-demo")
    previous.assert_not_called()
    assert result.puntaje.cobertura["persistencia_hallazgos"] is False


def test_solo_el_ultimo_escaneo_de_la_organizacion_permite_resolver():
    scan_id = UUID(int=1)
    finding_id = UUID(int=2)
    client = MagicMock()
    with (
        patch.object(main, "_supabase_client", return_value=client),
        patch.object(main, "_get_profile", return_value={"organizacion_id": "org-1", "rol": "analista"}),
        patch.object(main, "_get_scan", return_value={"estado": "completado", "finalizado_en": "2026-11-12T12:00:00Z"}),
        patch.object(main, "_execute", return_value={"id": "otro-escaneo"}),
        patch.object(main, "calcular_y_guardar") as calculate,
    ):
        try:
            asyncio.run(main.resolve_finding(scan_id, finding_id, SimpleNamespace(id="user-1")))
        except HTTPException as error:
            assert error.status_code == 409
        else:
            raise AssertionError("Se permitió resolver un hallazgo histórico")
    calculate.assert_not_called()


def test_hallazgo_retirado_no_se_puede_resolver_como_vigente():
    scan_id = UUID(int=1)
    finding_id = UUID(int=2)
    client = MagicMock()
    with (
        patch.object(main, "_supabase_client", return_value=client),
        patch.object(main, "_get_profile", return_value={"organizacion_id": "org-1", "rol": "analista"}),
        patch.object(main, "_get_scan", return_value={"estado": "completado", "finalizado_en": "2026-11-12T12:00:00Z"}),
        patch.object(main, "_execute", side_effect=[
            {"id": str(scan_id)},
            {"id": str(finding_id), "estado": "aceptado", "evidencia": {"retirado_del_riesgo": True}},
        ]),
        patch.object(main, "leer_riesgo", return_value={"cobertura": {"persistencia_hallazgos": True}}),
        patch.object(main, "calcular_y_guardar") as calculate,
    ):
        try:
            asyncio.run(main.resolve_finding(scan_id, finding_id, SimpleNamespace(id="user-1")))
        except HTTPException as error:
            assert error.status_code == 409
        else:
            raise AssertionError("Se permitió resolver un hallazgo fuera del riesgo vigente")
    calculate.assert_not_called()


def test_resolver_hallazgo_recalcula_el_puntaje_del_ultimo_escaneo():
    scan_id = UUID(int=1)
    finding_id = UUID(int=2)
    client = MagicMock()
    risk = main.RiskSummary(
        puntaje_global=0, infraestructura=0, identidad_digital=0,
        configuracion=0, fuga_de_datos=0,
    )
    with (
        patch.object(main, "_supabase_client", return_value=client),
        patch.object(main, "_get_profile", return_value={"organizacion_id": "org-1", "rol": "analista"}),
        patch.object(main, "_get_scan", return_value={"estado": "completado", "finalizado_en": "2026-11-12T12:00:00Z"}),
        patch.object(main, "_execute", side_effect=[
            {"id": str(scan_id)}, {"id": str(finding_id), "estado": "abierto"}, None,
        ]),
        patch.object(main, "leer_riesgo", return_value={"cobertura": {"persistencia_hallazgos": True}}),
        patch.object(main, "calcular_y_guardar") as calculate,
        patch.object(main, "_risk_or_none", return_value=risk),
        patch.object(main, "audit"),
    ):
        response = asyncio.run(main.resolve_finding(scan_id, finding_id, SimpleNamespace(id="user-1")))
    assert response.puntaje_global == 0
    calculate.assert_called_once_with(client, str(scan_id))


def test_consulta_recupera_puntaje_faltante_de_escaneo_terminado():
    client = MagicMock()
    score = main.RiskSummary(
        puntaje_global=17, infraestructura=17, identidad_digital=0,
        configuracion=0, fuga_de_datos=0, es_parcial=True,
    )
    with (
        patch.object(main, "_risk_or_none", side_effect=[None, None, score]) as read,
        patch.object(main, "scan_job_active", return_value=False),
        patch.object(main, "calculate_risk_with_retry", new_callable=AsyncMock) as calculate,
    ):
        result = asyncio.run(main._risk_or_recover(client, "scan-recovery", "incompleto"))
    assert result is score
    assert read.call_count == 3
    calculate.assert_awaited_once_with(client, "scan-recovery", attempts=2)


def test_consulta_no_duplica_calculo_mientras_el_trabajo_sigue_activo():
    with (
        patch.object(main, "_risk_or_none", return_value=None),
        patch.object(main, "scan_job_active", return_value=True),
        patch.object(main, "calculate_risk_with_retry", new_callable=AsyncMock) as calculate,
    ):
        result = asyncio.run(main._risk_or_recover(MagicMock(), "scan-active", "incompleto"))
    assert result is None
    calculate.assert_not_awaited()


def test_web_historico_no_se_puntua_ni_se_arrastra_tras_retirarlo():
    client = MagicMock()
    web_rule = Regla("regla-web", "CONF-006", "TLS inválido", "configuracion", "media", 12)
    web_obs = Obs("obs-web", "activo-web", "subdominio", "www.example.com", "info_host",
                  {"check": "tls_invalido", "verify_code": 62}, "Web", "fuente-web")
    previous = {
        "activo_id": "activo-web", "regla_id": "regla-web", "fuente_id": "fuente-web",
        "categoria": "configuracion", "severidad": "media", "confianza": 0.9,
        "evidencia": {"regla": "CONF-006", "detalle": {"activo": "www.example.com"}},
        "estado": "abierto",
    }
    with (
        patch("app.risk.persistencia.leer_riesgo", return_value=None),
        patch("app.risk.persistencia.cargar_observaciones", return_value=[web_obs]),
        patch("app.risk.persistencia.cargar_reglas", return_value=[web_rule]),
        patch("app.risk.persistencia.cargar_estado_fuentes", return_value={"Web": "completado"}),
        patch("app.risk.persistencia._alcance_escaneo", return_value="example.com"),
        patch("app.risk.persistencia._hallazgos_previos", return_value=("escaneo-anterior", [previous])),
        patch("app.risk.persistencia._resueltos_en_escaneo", return_value=set()),
    ):
        result = calcular_y_guardar(client, "escaneo-actual")
    assert result.hallazgos == []
    assert result.puntaje.puntaje_global == 0
    assert result.puntaje.cobertura["hallazgos_arrastrados"] == 0
    payload = client.rpc.call_args.args[1]
    assert payload["p_hallazgos"] == []
