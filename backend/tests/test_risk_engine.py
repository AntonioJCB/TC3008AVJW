import unittest
from datetime import datetime, timedelta, timezone

from app.risk.modelos import Hallazgo, Obs, Regla
from app.risk.motor import (
    CATEGORIAS, calcular_confianza, calcular_riesgo_confirmado,
    calcular_riesgo_global_estimado, calcular_riesgo_potencial, combinar_riesgos,
    evaluar_riesgo, puntuar_hallazgos,
)

AHORA = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
_contador = iter(range(1, 10_000))

CATALOGO = [
    Regla("r-infra1", "INFRA-001", "Administración remota expuesta", "infraestructura", "alta", 20),
    Regla("r-infra2", "INFRA-002", "Base de datos expuesta", "infraestructura", "critica", 30),
    Regla("r-infra3", "INFRA-003", "Vulnerabilidades conocidas", "infraestructura", "media", 10),
    Regla("r-conf1", "CONF-001", "Certificado expirado", "configuracion", "alta", 15),
    Regla("r-conf2", "CONF-002", "Certificado por expirar", "configuracion", "media", 8),
    Regla("r-iden3", "IDEN-003", "Correos expuestos", "identidad_digital", "baja", 5),
    Regla("r-conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, esta_activa=False),
    Regla("r-fuga1", "FUGA-001", "Secretos en repos", "fuga_de_datos", "critica", 30, esta_activa=False),
]
FUENTE_ID = {"Shodan": "f-shodan", "crt.sh": "f-crt", "SpiderFoot": "f-sf", "theHarvester": "f-th"}
TODAS_OK = {n: "completado" for n in FUENTE_ID}


def obs(tipo, valor, atributo, fuente="Shodan", **datos):
    return Obs(f"o{next(_contador)}", f"a-{tipo}-{valor}", tipo, valor, atributo, datos, fuente, FUENTE_ID.get(fuente, "f-web"))


def codigos(resultado):
    return sorted(h.regla_codigo for h in resultado.hallazgos)


def evaluar(observaciones, estado=None, reglas=CATALOGO):
    return evaluar_riesgo(observaciones, reglas, TODAS_OK if estado is None else estado, AHORA)


def finding(rule, asset, level, *, confidence=0.8, age=0, state="abierto", evidence=None):
    return Hallazgo(
        activo_id=asset, regla_id=rule.id, regla_codigo=rule.codigo,
        fuente_id="f-sf", categoria=rule.categoria, severidad=rule.severidad,
        confianza=confidence, evidencia=evidence or {}, estado=state,
        nivel_evidencia=level, antiguedad_dias=age,
        motivo_no_confirmado="Pendiente de confirmación." if level == "potencial" else None,
    )


class RiesgoGlobalTests(unittest.TestCase):
    def test_global_conserva_precision_y_distingue_niveles(self):
        r = Regla("r", "CONF-003", "SPF/DMARC", "configuracion", "baja", 1, True)
        confirmado = finding(r, "a", "confirmada", confidence=0.8)
        potencial = finding(r, "b", "potencial", confidence=0.01, age=360)
        resultado = calcular_riesgo_global_estimado([confirmado, potencial], [r])
        self.assertGreater(resultado["confirmado"], 0)
        self.assertGreater(resultado["potencial"], 0)
        self.assertGreater(resultado["puntaje_global"], resultado["confirmado"])
        self.assertEqual(len(resultado["contribuciones"]), 2)
        self.assertLess(resultado["contribuciones"][-1]["aporte"], 0.1)
        self.assertAlmostEqual(calcular_riesgo_confirmado([confirmado], [r])["puntaje_global"], 0.92)
        self.assertAlmostEqual(calcular_riesgo_potencial([potencial], [r])["puntaje_global"], 0.0025)
        self.assertAlmostEqual(resultado["contribuciones"][-1]["aporte"], 0.00125)

    def test_deduplica_y_descarta_resueltos_retirados_y_sin_atribucion(self):
        r = Regla("r", "CONF-003", "SPF/DMARC", "configuracion", "media", 10, True)
        confirmado = finding(r, "a", "confirmada")
        potencial_mismo = finding(r, "a", "potencial")
        resuelto = finding(r, "b", "confirmada", state="resuelto")
        retirado = finding(r, "c", "potencial", evidence={"retirado_del_riesgo": True})
        sin_activo = finding(r, "", "potencial")
        actual = calcular_riesgo_global_estimado([confirmado, confirmado, potencial_mismo, resuelto, retirado, sin_activo], [r])
        self.assertEqual(len(actual["contribuciones"]), 1)
        self.assertEqual(actual["contribuciones"][0]["nivel_evidencia"], "confirmada")
        self.assertEqual(actual["potencial"], 0)
        self.assertEqual(calcular_riesgo_global_estimado([resuelto, retirado, sin_activo], [r])["puntaje_global"], 0)

    def test_potencial_reciente_pesa_menos_y_disminuye_con_antiguedad(self):
        r = Regla("r", "CONF-003", "SPF/DMARC", "configuracion", "alta", 10, True)
        confirmado = calcular_riesgo_global_estimado([finding(r, "a", "confirmada")], [r])
        reciente = calcular_riesgo_global_estimado([finding(r, "a", "potencial")], [r])
        antiguo = calcular_riesgo_global_estimado([finding(r, "a", "potencial", age=360)], [r])
        self.assertGreater(confirmado["puntaje_global"], reciente["puntaje_global"])
        self.assertGreater(reciente["puntaje_global"], antiguo["puntaje_global"])
        self.assertEqual(calcular_riesgo_global_estimado([], [r])["puntaje_global"], 0)

    def test_actualizacion_y_sinteticos_en_los_tres_indicadores(self):
        regla = Regla("r", "CONF-003", "SPF/DMARC", "configuracion", "baja", 1)
        debil = finding(regla, "a", "confirmada", confidence=0.2)
        fuerte = finding(regla, "a", "confirmada", confidence=0.9)
        sinteticos = [finding(regla, "demo", nivel, evidence={"sintetico": True})
                      for nivel in ("confirmada", "potencial")]
        hallazgos = [debil, fuerte, *sinteticos]
        self.assertAlmostEqual(calcular_riesgo_confirmado(hallazgos, [regla])["puntaje_global"], 0.96)
        self.assertEqual(calcular_riesgo_potencial(hallazgos, [regla])["puntaje_global"], 0)
        self.assertAlmostEqual(calcular_riesgo_global_estimado(hallazgos, [regla])["puntaje_global"], 0.96)
        fuerte.estado = "resuelto"
        self.assertAlmostEqual(calcular_riesgo_global_estimado(hallazgos, [regla])["puntaje_global"], 0.68)


class RiesgoPotencialTests(unittest.TestCase):
    def test_separa_confirmado_potencial_activo_e_inactivo(self):
        active = Regla("pa", "CONF-004", "Cabeceras", "configuracion", "media", 20, True)
        inactive = Regla("pi", "CONF-008", "Redirección", "configuracion", "media", 30, False)
        confirmed = finding(active, "asset-confirmed", "confirmada")
        potential_active = finding(active, "asset-active", "potencial", confidence=0.8)
        potential_inactive = finding(inactive, "asset-inactive", "potencial", confidence=0.5, age=180)
        indicator = calcular_riesgo_potencial(
            [confirmed, potential_active, potential_inactive], [active, inactive],
        )
        self.assertEqual(indicator["hallazgos"], 2)
        self.assertEqual(indicator["reglas_activas"]["hallazgos"], 1)
        self.assertEqual(indicator["reglas_inactivas"]["hallazgos"], 1)
        self.assertGreater(indicator["puntaje_global"], 0)
        self.assertEqual(
            puntuar_hallazgos([confirmed, potential_active, potential_inactive], [active, inactive]),
            puntuar_hallazgos([confirmed], [active, inactive]),
        )

    def test_deduplica_y_considera_antiguedad_vigencia_y_atribucion(self):
        rule = Regla("p", "CONF-004", "Cabeceras", "configuracion", "media", 20, True)
        newer = finding(rule, "asset", "potencial", confidence=0.8, age=0)
        duplicate = finding(rule, "asset", "potencial", confidence=0.4, age=0)
        old = finding(rule, "old", "potencial", confidence=0.8, age=360)
        resolved = finding(rule, "resolved", "potencial", state="resuelto")
        retired = finding(rule, "retired", "potencial", evidence={"retirado_del_riesgo": True})
        no_asset = finding(rule, "", "potencial")
        indicator = calcular_riesgo_potencial(
            [newer, duplicate, old, resolved, retired, no_asset], [rule],
        )
        self.assertEqual(indicator["hallazgos"], 2)
        contributions = {item["activo_id"]: item for item in indicator["contribuciones"]}
        self.assertGreater(contributions["asset"]["aporte_potencial"], contributions["old"]["aporte_potencial"])

    def test_historico_sin_clasificacion_no_entra_en_ningun_indicador(self):
        rule = Regla("legacy", "INFRA-001", "Legacy", "infraestructura", "alta", 20, True)
        legacy = finding(rule, "asset", "sin_clasificar")
        self.assertEqual(calcular_riesgo_potencial([legacy], [rule])["puntaje_global"], 0)
        self.assertEqual(puntuar_hallazgos([legacy], [rule])["puntaje_global"], 0)


class ReglasDePuertosTests(unittest.TestCase):
    def test_ssh_expuesto_genera_infra_001_y_80_no(self):
        r = evaluar([
            obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", producto="OpenSSH"),
            obs("servicio", "203.0.113.10:80/tcp", "servicio_expuesto"),
        ])
        self.assertEqual(codigos(r), ["INFRA-001"])
        detalle = r.hallazgos[0].evidencia["detalle"]
        self.assertEqual((detalle["puerto"], detalle["tipo_servicio"], detalle["producto"]), (22, "SSH", "OpenSSH"))

    def test_base_de_datos_expuesta_genera_infra_002(self):
        r = evaluar([obs("servicio", "203.0.113.10:5432/tcp", "servicio_expuesto")])
        self.assertEqual(codigos(r), ["INFRA-002"])
        self.assertEqual(r.hallazgos[0].severidad, "critica")

    def test_ipv6_y_udp(self):
        r = evaluar([
            obs("servicio", "[2001:db8::1]:3389/tcp", "servicio_expuesto"),
            obs("servicio", "203.0.113.10:22/udp", "servicio_expuesto"),  # UDP no cuenta
        ])
        self.assertEqual(codigos(r), ["INFRA-001"])

    def test_corroboracion_sube_la_confianza_y_elige_fuente_principal(self):
        r = evaluar([
            obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", fuente="SpiderFoot"),
            obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", fuente="Shodan"),
        ])
        h = r.hallazgos[0]
        self.assertEqual(h.confianza, 0.85)  # 0.70 + 0.15
        self.assertEqual(h.evidencia["fuentes"], ["Shodan", "SpiderFoot"])
        self.assertEqual(h.fuente_id, "f-shodan")  # Shodan tiene prioridad


class CveTests(unittest.TestCase):
    def test_agrupa_los_cve_por_activo(self):
        r = evaluar([
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2018-15473", verificado=True),
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2020-0001", verificado=True, severidad_fuente="high", fuente="SpiderFoot"),
            obs("ip", "203.0.113.10", "cve", cve="CVE-2024-0001", verificado=True),
        ])
        self.assertEqual(codigos(r), ["INFRA-003", "INFRA-003"])
        por_activo = {h.evidencia["detalle"]["activo"]: h for h in r.hallazgos}
        self.assertEqual(por_activo["203.0.113.10:22/tcp"].evidencia["detalle"]["cves"], ["CVE-2018-15473", "CVE-2020-0001"])
        self.assertEqual(por_activo["203.0.113.10:22/tcp"].confianza, 0.65)  # 2 fuentes
        self.assertEqual(por_activo["203.0.113.10"].evidencia["detalle"]["cves"], ["CVE-2024-0001"])

    def test_misma_cve_en_ip_y_servicio_no_duplica_hallazgo(self):
        r = evaluar([
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2024-12345", verificado=True),
            obs("ip", "203.0.113.10", "cve", cve="CVE-2024-12345", verificado=True),
        ])
        self.assertEqual(codigos(r), ["INFRA-003"])
        self.assertEqual(r.hallazgos[0].evidencia["detalle"]["activo"], "203.0.113.10:22/tcp")

    def test_descarta_cve_no_verificada_por_la_fuente(self):
        r = evaluar([
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2024-12345", verificado=False),
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2024-12345", verificado=True, fuente="SpiderFoot"),
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2024-12345-extra"),
        ])
        self.assertEqual(codigos(r), ["INFRA-003"])
        self.assertEqual(r.hallazgos[0].evidencia["fuentes"], ["SpiderFoot"])
        self.assertTrue(r.hallazgos[0].evidencia["detalle"]["verificado_por_fuente"])

    def test_solo_cve_descartada_no_genera_puntaje(self):
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2024-12345", verificado=False)])
        self.assertEqual(r.hallazgos, [])
        self.assertEqual(r.puntaje.puntaje_global, 0)

    def test_false_none_y_sin_verificacion_se_conservan_pero_no_puntuan(self):
        for verification in (False, None, "missing"):
            details = {
                "cve": "CVE-2024-12345",
                "nvd": {"cvss": 9.8},
                "osv": {"id": "OSV-CONTROL"},
                "explotacion": {"kev": {"presente": True}, "epss": {"probabilidad": 0.9}},
                "evidencias_osint": [{"fuente": "urlscan", "referencia": "control"}],
            }
            if verification != "missing":
                details["verificado"] = verification
            observation = obs("subdominio", "api.example.com", "cve", fuente="SpiderFoot", **details)
            original = dict(observation.datos)
            result = evaluar([observation])
            with self.subTest(verificado=verification):
                self.assertEqual(result.hallazgos, [])
                self.assertEqual(result.puntaje.puntaje_global, 0)
                self.assertEqual(observation.datos, original)

    def test_true_explicito_sigue_generando_hallazgo(self):
        result = evaluar([obs(
            "subdominio", "api.example.com", "cve", fuente="SpiderFoot",
            cve="CVE-2024-12345", verificado=True,
        )])
        self.assertEqual(codigos(result), ["INFRA-003"])
        self.assertGreater(result.puntaje.puntaje_global, 0)


class CertificadosTests(unittest.TestCase):
    def cert(self, valor, hasta, desde="2026-01-01T00:00:00Z", serie="s", comodin=False):
        return obs("subdominio", valor, "certificado", fuente="crt.sh", valido_hasta=hasta, valido_desde=desde, serie=serie, comodin=comodin)

    def iso(self, dias):
        return (AHORA + timedelta(days=dias)).isoformat()

    def web(self, valor, check, **datos):
        return obs("subdominio", valor, "info_host", fuente="Web", check=check, **datos)

    def test_expirado_reciente(self):
        self.assertEqual(codigos(evaluar([self.cert("dev.ej.com", self.iso(-10))])), [])
        r = evaluar([self.cert("dev.ej.com", self.iso(-10)),
                    self.web("dev.ej.com", "tls_invalido", verify_code=10)])
        self.assertEqual(codigos(r), ["CONF-001"])
        self.assertEqual(r.hallazgos[0].evidencia["detalle"]["dias_vencido"], 10)

    def test_fallo_tls_por_nombre_distinto_no_prueba_certificado_vencido(self):
        self.assertEqual(codigos(evaluar([
            self.cert("www.ej.com", self.iso(-10)),
            self.web("www.ej.com", "tls_invalido", verify_code=62),
        ])), [])

    def test_expirado_hace_mucho_se_ignora_como_host_abandonado(self):
        self.assertEqual(codigos(evaluar([self.cert("viejo.ej.com", self.iso(-400))])), [])

    def test_un_certificado_viejo_no_cuenta_si_hay_uno_vigente(self):
        r = evaluar([self.cert("www.ej.com", self.iso(-10), serie="viejo"), self.cert("www.ej.com", self.iso(80), serie="nuevo")])
        self.assertEqual(codigos(r), [])

    def test_certificado_comodin_vigente_cubre_al_nombre_con_cert_viejo(self):
        r = evaluar([self.cert("ej.com", self.iso(-5), serie="apex"), self.cert("ej.com", self.iso(60), serie="wildcard", comodin=True)])
        self.assertEqual(codigos(r), [])

    def test_por_expirar_en_30_dias(self):
        self.assertEqual(codigos(evaluar([self.cert("api.ej.com", self.iso(12))])), [])
        self.assertEqual(codigos(evaluar([
            self.cert("api.ej.com", self.iso(12)),
            self.web("api.ej.com", "tls_verificado", valid_until=self.iso(12)),
        ])), ["CONF-002"])
        self.assertEqual(codigos(evaluar([self.cert("api.ej.com", self.iso(45))])), [])

    def test_fechas_invalidas_no_rompen(self):
        self.assertEqual(codigos(evaluar([self.cert("x.ej.com", "no-es-fecha")])), [])


class CorreosTests(unittest.TestCase):
    def test_un_hallazgo_por_correo_corroborado_por_dos_fuentes(self):
        r = evaluar([
            obs("correo", "ventas@ej.com", "descubierto", fuente="theHarvester"),
            obs("correo", "ventas@ej.com", "descubierto", fuente="SpiderFoot"),
            obs("correo", "soporte@ej.com", "descubierto", fuente="theHarvester"),
        ])
        self.assertEqual(codigos(r), ["IDEN-003", "IDEN-003"])
        self.assertEqual(sorted(h.confianza for h in r.hallazgos), [0.8, 0.95])


class PosturaDnsTests(unittest.TestCase):
    def dns(self, valor, check, issues, estado="present"):
        return obs("dominio", valor, "info_host", fuente="SpiderFoot", tipo_evento="DNS_POSTURE",
                   check=check, estado=estado, issues=issues)

    def test_conf_003_solo_consume_problemas_explicitos_y_evaluables(self):
        active = [Regla(r.id, r.codigo, r.nombre, r.categoria, r.severidad, r.peso,
                        True if r.codigo == "CONF-003" else r.esta_activa) for r in CATALOGO]
        candidate = {"code": "SPF_ALLOW_ALL", "message": "+all", "severity": "alta",
                     "evaluable": True, "rule": "CONF-003"}
        informational = {"code": "DNSSEC_UNVERIFIED", "message": "sin AD", "severity": "informativa",
                         "evaluable": False, "rule": None}
        result = evaluar([self.dns("ej.com", "spf", [candidate]),
                          self.dns("ej.com", "dnssec", [informational], "unverified")], reglas=active)
        self.assertEqual(codigos(result), ["CONF-003"])
        self.assertEqual(result.hallazgos[0].evidencia["detalle"]["problemas_dns"][0]["code"], "SPF_ALLOW_ALL")

    def test_regla_inactiva_conserva_evidencia_como_potencial_sin_puntuar(self):
        issue = {"code": "DMARC_MONITOR_ONLY", "message": "p=none", "severity": "media",
                 "evaluable": True, "rule": "CONF-003"}
        result = evaluar([self.dns("ej.com", "dmarc", [issue])])
        self.assertIn("CONF-003", codigos(result))
        finding = next(item for item in result.hallazgos if item.regla_codigo == "CONF-003")
        self.assertEqual(finding.nivel_evidencia, "potencial")
        self.assertIn("regla permanece inactiva", finding.motivo_no_confirmado)
        self.assertEqual(result.puntaje.puntaje_global, 0)
        self.assertGreater(result.puntaje.cobertura["riesgo_potencial"]["puntaje_global"], 0)
        self.assertEqual({row["codigo"]: row["motivo"] for row in result.puntaje.cobertura["no_evaluadas"]}["CONF-003"], "inactiva")


class PuntajesTests(unittest.TestCase):
    def test_senales_informativas_se_guardan_sin_aumentar_el_score(self):
        reglas = [
            Regla(r.id, r.codigo, r.nombre, r.categoria, r.severidad, 0 if r.codigo in {"CONF-001", "CONF-002", "IDEN-003"} else r.peso, r.esta_activa)
            for r in CATALOGO
        ]
        r = evaluar([
            obs("subdominio", "api.ej.com", "certificado", fuente="crt.sh", valido_hasta=(AHORA - timedelta(days=2)).isoformat()),
            obs("correo", "contacto@ej.com", "descubierto", fuente="theHarvester"),
        ], reglas=reglas)
        self.assertEqual(codigos(r), ["IDEN-003"])
        self.assertEqual(r.puntaje.puntaje_global, 0)

    def test_combinar_riesgos(self):
        self.assertEqual(combinar_riesgos([]), 0)
        self.assertAlmostEqual(combinar_riesgos([50, 50]), 75)
        self.assertEqual(combinar_riesgos([100, 30]), 100)
        self.assertEqual(combinar_riesgos([-5, 250]), 100)  # se acota

    def test_la_confianza_tiene_techo(self):
        self.assertEqual(calcular_confianza(0.9, 5), 0.99)
        self.assertEqual(calcular_confianza(0.7, 0), 0.7)

    def test_sin_observaciones_el_puntaje_es_cero(self):
        p = evaluar([]).puntaje
        self.assertEqual((p.puntaje_global, p.infraestructura, p.configuracion), (0, 0, 0))
        self.assertFalse(p.es_parcial)

    def test_mas_hallazgos_nunca_bajan_el_puntaje_y_no_pasan_de_100(self):
        base = [obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto")]
        mas = base + [obs("servicio", "203.0.113.10:5432/tcp", "servicio_expuesto")]
        masmas = mas + [obs("servicio", f"203.0.113.10:{p}/tcp", "servicio_expuesto") for p in (23, 3389, 6379, 27017, 9200)]
        g = [evaluar(o).puntaje.puntaje_global for o in (base, mas, masmas)]
        self.assertTrue(0 < g[0] < g[1] < g[2] <= 100, g)

    def test_los_puntajes_son_enteros_entre_0_y_100(self):
        p = evaluar([obs("servicio", f"203.0.113.10:{pt}/tcp", "servicio_expuesto") for pt in (22, 23, 3389, 5432, 6379)]).puntaje
        for valor in (p.puntaje_global, *(getattr(p, c) for c in CATEGORIAS)):
            self.assertIsInstance(valor, int)
            self.assertTrue(0 <= valor <= 100)

    def test_es_determinista(self):
        o = [obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto"), obs("correo", "a@ej.com", "descubierto", fuente="theHarvester")]
        self.assertEqual(evaluar(o).puntaje.como_dict(), evaluar(o).puntaje.como_dict())

    def test_cambiar_el_peso_en_la_base_cambia_el_puntaje_sin_tocar_codigo(self):
        o = [obs("servicio", "203.0.113.10:5432/tcp", "servicio_expuesto")]
        mas_pesado = [Regla(r.id, r.codigo, r.nombre, r.categoria, r.severidad, 60 if r.codigo == "INFRA-002" else r.peso) for r in CATALOGO]
        self.assertGreater(evaluar(o, reglas=mas_pesado).puntaje.puntaje_global, evaluar(o).puntaje.puntaje_global)


class CoberturaYFuentesTests(unittest.TestCase):
    def motivos(self, r):
        return {n["codigo"]: n["motivo"] for n in r.puntaje.cobertura["no_evaluadas"]}

    def test_cobertura_distingue_inactiva_y_sin_evaluador(self):
        c = evaluar([]).puntaje.cobertura
        self.assertEqual(c["total_reglas"], 8)
        self.assertEqual(c["reglas_activas"], 6)
        self.assertEqual(c["evaluadas"], ["CONF-001", "CONF-002", "IDEN-003", "INFRA-001", "INFRA-002", "INFRA-003"])
        self.assertEqual(self.motivos(evaluar([])), {"CONF-003": "inactiva", "FUGA-001": "inactiva"})
        self.assertEqual(c["porcentaje_evaluadas"], 100)

    def test_si_falla_shodan_pero_spiderfoot_responde_las_reglas_de_infra_se_evaluan_igual(self):
        estado = {**TODAS_OK, "Shodan": "fallido"}
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", fuente="SpiderFoot")], estado)
        self.assertEqual(codigos(r), ["INFRA-001"])
        self.assertTrue(r.puntaje.es_parcial)
        self.assertEqual(r.puntaje.fuentes_faltantes, ["Shodan"])

    def test_fuente_parcial_con_evidencia_contribuye_y_baja_cobertura(self):
        estado = {**TODAS_OK, "SpiderFoot": "parcial"}
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", fuente="SpiderFoot")], estado)
        self.assertGreater(r.puntaje.puntaje_global, 0)
        self.assertTrue(r.puntaje.es_parcial)
        self.assertIn("SpiderFoot", r.puntaje.fuentes_faltantes)

    def test_si_fallan_todas_las_fuentes_de_una_regla_no_se_da_por_limpia(self):
        estado = {**TODAS_OK, "Shodan": "fallido", "SpiderFoot": "fallido"}
        r = evaluar([], estado)
        self.assertEqual(self.motivos(r)["INFRA-001"], "fuentes_fallidas")
        self.assertNotIn("INFRA-001", r.puntaje.cobertura["evaluadas"])
        self.assertIn("CONF-001", r.puntaje.cobertura["evaluadas"])  # crt.sh sí terminó
        self.assertEqual(r.puntaje.fuentes_faltantes, ["Shodan", "SpiderFoot"])

    def test_una_fuente_aun_ejecutando_cuenta_como_faltante(self):
        r = evaluar([], {**TODAS_OK, "crt.sh": "ejecutando"})
        self.assertTrue(r.puntaje.es_parcial)
        self.assertEqual(self.motivos(r)["CONF-001"], "fuentes_fallidas")

    def test_fuente_deshabilitada_informa_cobertura_sin_alterar_los_puntajes(self):
        estado = {**TODAS_OK, "crt.sh": "deshabilitado"}
        baseline = evaluar([], {name: value for name, value in estado.items() if name != "crt.sh"})
        result = evaluar([], estado)
        self.assertFalse(result.puntaje.es_parcial)
        self.assertEqual(result.puntaje.puntaje_global, baseline.puntaje.puntaje_global)
        self.assertEqual(result.puntaje.cobertura["riesgo_potencial"], baseline.puntaje.cobertura["riesgo_potencial"])
        self.assertEqual(result.puntaje.cobertura["fuentes_deshabilitadas"], ["crt.sh"])

    def test_sin_informacion_de_fuentes_se_evalua_todo_y_no_es_parcial(self):
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto")], estado={})
        self.assertEqual(codigos(r), ["INFRA-001"])
        self.assertFalse(r.puntaje.es_parcial)

    def test_categoria_invalida_no_rompe_el_motor(self):
        malas = [Regla("r-x", "INFRA-001", "x", "inventada", "alta", 20)]
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto")], reglas=malas)
        self.assertEqual(r.hallazgos, [])
        self.assertEqual(self.motivos(r)["INFRA-001"], "categoria_invalida")


if __name__ == "__main__":
    unittest.main()
