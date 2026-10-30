import unittest
from datetime import datetime, timedelta, timezone

from app.risk.modelos import Obs, Regla
from app.risk.motor import (
    CATEGORIAS, calcular_confianza, combinar_riesgos, evaluar_riesgo,
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
    Regla("r-conf3", "CONF-003", "SPF/DMARC", "configuracion", "media", 10),  # sin evaluador
    Regla("r-fuga1", "FUGA-001", "Secretos en repos", "fuga_de_datos", "critica", 30, esta_activa=False),
]
FUENTE_ID = {"Shodan": "f-shodan", "crt.sh": "f-crt", "SpiderFoot": "f-sf", "theHarvester": "f-th"}
TODAS_OK = {n: "completado" for n in FUENTE_ID}


def obs(tipo, valor, atributo, fuente="Shodan", **datos):
    return Obs(f"o{next(_contador)}", f"a-{tipo}-{valor}", tipo, valor, atributo, datos, fuente, FUENTE_ID[fuente])


def codigos(resultado):
    return sorted(h.regla_codigo for h in resultado.hallazgos)


def evaluar(observaciones, estado=None, reglas=CATALOGO):
    return evaluar_riesgo(observaciones, reglas, TODAS_OK if estado is None else estado, AHORA)


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
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2018-15473"),
            obs("servicio", "203.0.113.10:22/tcp", "cve", cve="CVE-2020-0001", severidad_fuente="high", fuente="SpiderFoot"),
            obs("ip", "203.0.113.10", "cve", cve="CVE-2024-0001"),
        ])
        self.assertEqual(codigos(r), ["INFRA-003", "INFRA-003"])
        por_activo = {h.evidencia["detalle"]["activo"]: h for h in r.hallazgos}
        self.assertEqual(por_activo["203.0.113.10:22/tcp"].evidencia["detalle"]["cves"], ["CVE-2018-15473", "CVE-2020-0001"])
        self.assertEqual(por_activo["203.0.113.10:22/tcp"].confianza, 0.65)  # 2 fuentes


class CertificadosTests(unittest.TestCase):
    def cert(self, valor, hasta, desde="2026-01-01T00:00:00Z", serie="s", comodin=False):
        return obs("subdominio", valor, "certificado", fuente="crt.sh", valido_hasta=hasta, valido_desde=desde, serie=serie, comodin=comodin)

    def iso(self, dias):
        return (AHORA + timedelta(days=dias)).isoformat()

    def test_expirado_reciente(self):
        r = evaluar([self.cert("dev.ej.com", self.iso(-10))])
        self.assertEqual(codigos(r), ["CONF-001"])
        self.assertEqual(r.hallazgos[0].evidencia["detalle"]["dias_vencido"], 10)

    def test_expirado_hace_mucho_se_ignora_como_host_abandonado(self):
        self.assertEqual(codigos(evaluar([self.cert("viejo.ej.com", self.iso(-400))])), [])

    def test_un_certificado_viejo_no_cuenta_si_hay_uno_vigente(self):
        r = evaluar([self.cert("www.ej.com", self.iso(-10), serie="viejo"), self.cert("www.ej.com", self.iso(80), serie="nuevo")])
        self.assertEqual(codigos(r), [])

    def test_certificado_comodin_vigente_cubre_al_nombre_con_cert_viejo(self):
        r = evaluar([self.cert("ej.com", self.iso(-5), serie="apex"), self.cert("ej.com", self.iso(60), serie="wildcard", comodin=True)])
        self.assertEqual(codigos(r), [])

    def test_por_expirar_en_30_dias(self):
        self.assertEqual(codigos(evaluar([self.cert("api.ej.com", self.iso(12))])), ["CONF-002"])
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


class PuntajesTests(unittest.TestCase):
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
        self.assertEqual(c["evaluadas"], ["CONF-001", "CONF-002", "IDEN-003", "INFRA-001", "INFRA-002", "INFRA-003"])
        self.assertEqual(self.motivos(evaluar([])), {"CONF-003": "sin_evaluador", "FUGA-001": "inactiva"})
        self.assertEqual(c["porcentaje_evaluadas"], 75)

    def test_si_falla_shodan_pero_spiderfoot_responde_las_reglas_de_infra_se_evaluan_igual(self):
        estado = {**TODAS_OK, "Shodan": "fallido"}
        r = evaluar([obs("servicio", "203.0.113.10:22/tcp", "servicio_expuesto", fuente="SpiderFoot")], estado)
        self.assertEqual(codigos(r), ["INFRA-001"])
        self.assertTrue(r.puntaje.es_parcial)
        self.assertEqual(r.puntaje.fuentes_faltantes, ["Shodan"])

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
