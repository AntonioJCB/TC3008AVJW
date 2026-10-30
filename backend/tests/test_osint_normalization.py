import unittest

from app.osint_normalization import (
    adaptar,
    clasificar_dominio,
    deduplicar_local,
    fecha_iso,
    hash_contenido,
    normalizar_correo,
    normalizar_dominio,
    normalizar_ip,
    parsear_servicio,
    valor_servicio,
)


DOMAIN = "ejemplo.com"


class NormalizationTests(unittest.TestCase):
    def test_domain_idn_wildcard_and_scope(self) -> None:
        self.assertEqual(normalizar_dominio(" *.Bücher.Ejemplo.com. "), ("xn--bcher-kva.ejemplo.com", True))
        self.assertEqual(clasificar_dominio("api.ejemplo.com", DOMAIN), "subdominio")
        self.assertIsNone(clasificar_dominio("otroejemplo.com", DOMAIN))

    def test_ip_service_email_and_date(self) -> None:
        self.assertEqual(normalizar_ip("2001:DB8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertIsNone(normalizar_ip("01.2.3.4"))
        self.assertEqual(valor_servicio("1.2.3.4", 443, "TCP"), "1.2.3.4:443/tcp")
        self.assertEqual(parsear_servicio("[2001:db8::1]:53/udp"), {
            "ip": "2001:db8::1", "puerto": 53, "protocolo": "udp"
        })
        self.assertEqual(normalizar_correo("mailto:Admin@EJEMPLO.com"), "admin@ejemplo.com")
        self.assertEqual(fecha_iso("2026-01-01T00:00:00"), "2026-01-01T00:00:00.000Z")

    def test_hash_and_dedupe(self) -> None:
        self.assertEqual(hash_contenido({"a": 1, "b": {"c": 2}}), hash_contenido({"b": {"c": 2}, "a": 1}))
        observation = {
            "tipo": "subdominio", "valor": "api.ejemplo.com", "atributo": "descubierto", "datos": {}
        }
        deduplicated = deduplicar_local([
            {**observation, "observado_en": "2026-10-05T00:00:00.000Z"},
            {**observation, "observado_en": "2026-10-01T00:00:00.000Z"},
        ])
        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0]["observado_en"], "2026-10-01T00:00:00.000Z")

    def test_crtsh_preserves_wildcard_certificate_fact(self) -> None:
        result = adaptar(
            "crt.sh",
            [{
                "id": 1,
                "common_name": "ejemplo.com",
                "name_value": "ejemplo.com\n*.ejemplo.com\napi.ejemplo.com\notro.org",
                "not_before": "2026-09-01T00:00:00",
                "not_after": "2026-11-30T00:00:00",
            }],
            DOMAIN,
        )
        self.assertEqual(
            sorted((item["tipo"], item["valor"]) for item in result["observaciones"] if item["atributo"] == "descubierto"),
            [("dominio", "ejemplo.com"), ("subdominio", "api.ejemplo.com")],
        )
        certificates = [item for item in result["observaciones"] if item["atributo"] == "certificado"]
        self.assertEqual(sorted(item["datos"]["comodin"] for item in certificates), [False, False, True])
        self.assertEqual(result["descartadas"], [{"motivo": "fuera_de_alcance", "entrada": "otro.org"}])

    def test_shodan_match_payload_is_adapted_and_third_party_hostname_discarded(self) -> None:
        raw = {
            "matches": [{
                "ip_str": "203.0.113.10",
                "hostnames": ["api.ejemplo.com", "otro-sitio.net"],
                "domains": ["ejemplo.com"],
                "vulns": ["CVE-2024-0001"],
                "data": [{
                    "port": 22,
                    "product": "OpenSSH",
                    "version": "7.4",
                    "vulns": {"CVE-2018-15473": {"verified": False}},
                }],
            }],
            "total": 1,
        }
        result = adaptar("Shodan", raw, DOMAIN)
        self.assertIn("ip:203.0.113.10", [f"{item['tipo']}:{item['valor']}" for item in result["observaciones"]])
        self.assertIn("servicio:203.0.113.10:22/tcp", [f"{item['tipo']}:{item['valor']}" for item in result["observaciones"]])
        self.assertEqual(
            [item["datos"]["cve"] for item in result["observaciones"] if item["atributo"] == "cve"],
            ["CVE-2024-0001", "CVE-2018-15473"],
        )
        self.assertEqual(result["descartadas"], [{"motivo": "fuera_de_alcance", "entrada": "otro-sitio.net"}])

    def test_theharvester_normalizes_and_discards_out_of_scope_email(self) -> None:
        result = adaptar(
            "theHarvester",
            {
                "hosts": ["mail.ejemplo.com:203.0.113.20", "203.0.113.30", "ajeno.net:1.1.1.1"],
                "ips": [],
                "emails": ["Soporte@Ejemplo.com", "x@otro.org"],
                "asns": ["AS64500"],
            },
            DOMAIN,
        )
        values = {f"{item['tipo']}:{item['valor']}" for item in result["observaciones"]}
        self.assertEqual(values, {
            "correo:soporte@ejemplo.com",
            "ip:203.0.113.20",
            "ip:203.0.113.30",
            "subdominio:mail.ejemplo.com",
        })
        self.assertEqual(len([item for item in result["observaciones"] if item["atributo"] == "resuelve_a"]), 1)

    def test_spiderfoot_maps_cve_to_parent_service_and_handles_email_alias(self) -> None:
        result = adaptar(
            "SpiderFoot",
            [
                {"event_type": "INTERNET_NAME", "data": "api.ejemplo.com", "source_data": DOMAIN},
                {"event_type": "EMAIL_ADDRESS", "data": "admin@ejemplo.com"},
                {"type": "TCP_PORT_OPEN", "data": "203.0.113.40:8080"},
                {
                    "type": "VULNERABILITY_CVE_HIGH",
                    "data": "CVE-2021-41773\nPath traversal",
                    "source": "203.0.113.40:8080",
                },
                {"type": "VULNERABILITY_CVE_LOW", "data": "CVE-2020-1111", "source": "unmatched"},
            ],
            DOMAIN,
        )
        values = {f"{item['tipo']}:{item['valor']}" for item in result["observaciones"]}
        self.assertIn("correo:admin@ejemplo.com", values)
        cve = next(item for item in result["observaciones"] if item["atributo"] == "cve")
        self.assertEqual(cve["valor"], "203.0.113.40:8080/tcp")
        self.assertEqual(cve["datos"]["severidad_fuente"], "high")
        self.assertIn("sin_activo_asociado", [item["motivo"] for item in result["descartadas"]])


if __name__ == "__main__":
    unittest.main()

class ShodanSearchMatchesTest(unittest.TestCase):
    """/shodan/host/search devuelve un banner por entrada, no un host con data[]."""

    def test_matches_de_busqueda_producen_servicios_y_cves(self):
        from app.osint_normalization import adaptar

        raw = {
            "total": 2,
            "matches": [
                {
                    "ip_str": "203.0.113.10", "port": 22, "transport": "tcp",
                    "product": "OpenSSH", "version": "7.4", "hostnames": ["dev.ejemplo.com"],
                    "domains": ["ejemplo.com"], "timestamp": "2026-10-10T07:00:00.000000",
                    "data": "SSH-2.0-OpenSSH_7.4", "vulns": {"CVE-2018-15473": {"verified": False}},
                },
                {
                    "ip_str": "203.0.113.10", "port": 5432, "transport": "tcp",
                    "product": "PostgreSQL", "hostnames": ["dev.ejemplo.com"],
                    "domains": ["ejemplo.com"], "data": "PostgreSQL",
                },
            ],
        }
        result = adaptar("Shodan", raw, "ejemplo.com")
        services = {o["valor"] for o in result["observaciones"] if o["tipo"] == "servicio"}
        cves = {o["datos"]["cve"] for o in result["observaciones"] if o["atributo"] == "cve"}
        self.assertEqual(services, {"203.0.113.10:22/tcp", "203.0.113.10:5432/tcp"})
        self.assertEqual(cves, {"CVE-2018-15473"})
