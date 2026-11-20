# SpiderFoot pasivo: implementación del 18 de noviembre de 2026

## Perfil implementado

| Módulo | Objetivo | Evidencia | Requisito | Uso en Risk Score |
|---|---|---|---|---|
| `sfp_dnsresolve`, `sfp_dnsraw`, `sfp_robtex`, `sfp_crobat_api` | Dominio o subdominio autorizado | Nombres, registros y relaciones DNS | Sin clave | Descubrimiento y relaciones; no demuestra exposición ni vulnerabilidad. |
| `sfp_baxter_dns_doh` | Dominio o subdominio autorizado | A, AAAA, CNAME, MX, TXT, CAA, NS, SOA, DS, SPF, DMARC, MTA-STS, TLS-RPT y validación AD | Google Public DNS JSON API, sin clave | Observaciones estructuradas. Solo problemas explícitos marcados como evaluables pueden llegar al evaluador de `CONF-003`; la regla sigue controlada por el catálogo. |
| `sfp_baxter_urlscan` | Dominio o subdominio autorizado | Banners web históricos y fecha del registro | Sin clave; sujeto a cuotas de búsqueda | Informativo. Un banner no demuestra una vulnerabilidad. |
| `sfp_baxter_internetdb` | IP pública autorizada explícitamente | Puertos sin transporte, CPE y referencias CVE | Declaración `noncommercial` o licencia comercial | Informativo. InternetDB mezcla CVE verificadas y no verificadas y no indica transporte; no puntúa. |
| `sfp_baxter_shodan` | IP pública autorizada explícitamente | Servicios TCP/UDP, banners, producto, versión y CVE | Clave con acceso al endpoint Host | Los servicios TCP y las CVE marcadas `verified=true` llegan a las reglas existentes. |

Los módulos usan `requests`, dependencia ya incluida en la imagen fijada de
SpiderFoot; no añaden paquetes del sistema ni bibliotecas de pago.

## Módulos instalados revisados

| Familia instalada | Decisión | Motivo |
|---|---|---|
| `sfp_urlscan` | Sustituido por `sfp_baxter_urlscan` | La versión instalada puede resolver nombres cuando `verify=true` y entrega el banner sin una atribución estructurada suficiente para el reporte. |
| `sfp_shodan` | Sustituido por `sfp_baxter_shodan` | Es pasivo y útil, pero exige API key. El adaptador acotado conserva transporte, fecha, activo y `verified` sin activar búsquedas amplias. |
| `sfp_censys`, `sfp_binaryedge`, `sfp_leakix`, `sfp_onyphe`, `sfp_fullhunt`, `sfp_builtwith`, `sfp_pulsedive` | No habilitados | Requieren credenciales o plan. Algunos conectores pertenecen a la versión fijada de SpiderFoot y deben comprobarse contra la API vigente antes de desplegarlos. |
| `sfp_webserver`, `sfp_strangeheaders` | No habilitados | Solo analizan cabeceras obtenidas por otro módulo; no recopilan evidencia por sí mismos y requerirían un productor que contacte al sitio. |
| Nuclei, RetireJS, Wappalyzer, spider/crawler | Rechazados por el perfil | Contactan o inspeccionan directamente el activo y no cumplen el alcance estrictamente pasivo. |
| `sfp_openbugbounty`, `sfp_h1nobbdde`, `sfp_punkspider` | No habilitados | Sus avisos generales no aportan, en esta versión, una atribución verificable de servicio, versión y CVE suficiente para las reglas vigentes. |

Los tres módulos consultan bases de proveedores. No abren sockets al activo,
no envían solicitudes HTTP al sitio y no expanden el objetivo con vecinos o
IPs compartidas. Cada ejecución emite un sobre versionado
`baxter-passive-v1`; el backend solo acepta eventos cuyo objetivo coincide
exactamente con `scan_target`.

## Alcance y normalización

El orquestador toma dominios, subdominios, IPs y servicios del inventario de
Relaciones. Un servicio se consulta mediante su IP. Los nombres deben pertenecer
al dominio autorizado; las IPs requieren una IP o CIDR explícita en la
autorización. `SCAN_MAX_TARGETS` sigue siendo el límite operativo: los activos
que exceden el límite aparecen como pendientes y no como evaluados.

Los banners, software, versiones, CPE y puertos sin transporte se guardan como
`info_host`. Los puertos con transporte crean `servicio_expuesto`. Las CVE se
guardan con el indicador `verificado` del proveedor. Las reglas y sus pesos no
se modificaron: una CVE con `verificado=false` no activa `INFRA-003`.

## Configuración

El valor seguro de `backend/.env` es:

```dotenv
SPIDERFOOT_MODULES=sfp_dnsresolve,sfp_dnsraw,sfp_robtex,sfp_crobat_api,sfp_baxter_dns_doh,sfp_baxter_urlscan
```

Para proveedores de IP, copia `spiderfoot.env.example` como `spiderfoot.env`,
configura solamente las variables aplicables y añade los módulos autorizados a
`SPIDERFOOT_MODULES`. El archivo real está excluido de Git. Cambiar módulos o
variables requiere recrear backend y SpiderFoot; no se aplican a contenedores
ya iniciados.

Si la red inspecciona HTTPS, coloca únicamente la CA raíz pública en
`deploy/spiderfoot-ca/` y configura `SPIDERFOOT_CA_BUNDLE` con su ruta montada
bajo `/opt/baxtersec-ca`. Los certificados locales están ignorados por Git. No
se admite desactivar la verificación TLS.

## Evidencia de pruebas

`backend/tests/test_spiderfoot_passive.py` cubre respuestas correctas, vacías,
parciales, 401/403/429/500, JSON inválido, atribución a otra IP, IPv6, licencia,
ausencia de clave, `false_positive`, alcance, presupuesto de objetivos,
persistencia de errores y recorrido hasta el Risk Score. El script
`backend/tests/check_spiderfoot_runtime.py` carga los módulos locales usando las
clases de la versión de SpiderFoot instalada y HTTP simulado. Su evidencia está
en `docs/backend/spiderfoot-runtime-20261118.json`.

No se reconstruyeron contenedores, no se ejecutó un análisis real y no se
escribió en Supabase durante esta validación.

La afirmación anterior corresponde a la validación original del 18 de noviembre.
La incorporación posterior de DNS DoH y su validación se documenta en
`dns-doh-pasivo-20261119.md`.

## Referencias de proveedores

- urlscan: [Search API](https://docs.urlscan.io/apis/urlscan-openapi/search) y
  [cuotas y límites](https://docs.urlscan.io/pages/api-rate-limits).
- Shodan: [Host Information](https://developer.shodan.io/api#host-information).
- InternetDB: [API, frecuencia, licencia y alcance de datos](https://internetdb.shodan.io/)
  y [estructura de la respuesta](https://book.shodan.io/developer-apis/internetdb/).
- Google Public DNS: [JSON API de DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/doh/json),
  [preguntas frecuentes y ausencia de SLA](https://developers.google.com/speed/public-dns/faq)
  y [términos de las APIs de Google](https://developers.google.com/terms/).
