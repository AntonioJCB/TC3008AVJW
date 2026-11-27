# Postura DNS pasiva mediante Google Public DNS DoH

Implementación del 19 de noviembre de 2026 para el proyecto académico BaxterSec.

## Alcance

`sfp_baxter_dns_doh` recibe únicamente el objetivo exacto que el orquestador ya
seleccionó del inventario autorizado. El módulo consulta el endpoint JSON
`https://dns.google/resolve`; no visita el sitio, no abre puertos, no solicita
escaneos a terceros y no expande la ejecución a nombres encontrados en las
respuestas.

Por cada dominio o subdominio consulta A, AAAA, CNAME, MX, TXT, CAA, NS, SOA y
DS, además de los nombres exactos `_dmarc`, `_mta-sts` y `_smtp._tls`. Cada
comprobación conserva nombre, tipo, estado, RCODE, registros, TTL, fecha,
consulta, validación DNSSEC `AD`, interpretación y problemas detectados.

Los estados son:

- `present`: existe al menos un registro exacto del tipo solicitado;
- `absent`: la respuesta DNS fue concluyente y no contiene el registro exacto;
- `error`: falló HTTP, el formato, o DNS devolvió un RCODE no concluyente;
- `unverified`: no hay base técnica suficiente para afirmar presencia o ausencia;
- `not_applicable`: la comprobación no aplica, por ejemplo A exacto cuando el
  nombre publica CNAME.

## Atribución y significado de seguridad

Solo se aceptan entradas de `Answer` cuyo propietario y tipo coinciden con la
consulta. Los destinos CNAME, MX y NS quedan dentro de la evidencia del registro,
pero no se convierten en activos del cliente. Esto evita atribuir Vercel u otro
proveedor de alojamiento al inventario autorizado.

SPF se extrae de TXT exactos. Se identifican políticas múltiples, `+all`, `?all`,
`~all` y políticas sin un `all` terminal. La ausencia de SPF solo queda como
evidencia candidata cuando el mismo nombre publica un MX no nulo. DMARC evalúa
políticas exactas presentes, incluyendo `p=none`, `pct` parcial y formatos
inválidos. Si `_dmarc` no existe, el estado pasa a `unverified`: una política del
dominio organizacional podría heredarse y BaxterSec no la atribuye sin resolver
esa relación de propiedad.

DKIM queda siempre `unverified` mientras no exista un selector conocido; no se
enumeran selectores ni se afirma ausencia. CAA, MTA-STS, TLS-RPT y DNSSEC aportan
contexto, pero su ausencia no activa `CONF-003`. `AD=false` tampoco se interpreta
como DNSSEC inseguro.

## Normalización y Risk Score

Cada comprobación produce un evento `DNS_POSTURE` y una observación `info_host`
relacionada con el dominio o subdominio exacto. Los problemas incluyen un código,
mensaje, severidad informativa, regla candidata y un indicador `evaluable`.

El evaluador de `CONF-003` consume exclusivamente problemas con
`rule=CONF-003` y `evaluable=true`. Añadir el evaluador no activa la regla ni
modifica su peso: ambas decisiones siguen en `reglas_riesgo` de Supabase. En el
estado revisado la regla permanece inactiva, por lo que las observaciones se
guardan y explican sin aumentar el puntaje. No se creó ni ejecutó una migración.

## Reporte

El reporte general y la vista por activo muestran el estado de cada comprobación,
su interpretación, registros exactos, TTL, fecha, validación DNSSEC y problemas.
Una evidencia preparada para `CONF-003` se identifica como candidata y no se
presenta como hallazgo mientras la regla continúe inactiva. Los errores y estados
no verificables se distinguen de resultados ausentes.

SpiderFoot limita el tamaño exportable de un evento. El primer ensayo real
truncó el sobre monolítico y el backend lo rechazó correctamente como JSON
inválido. La implementación definitiva emite un resumen y una comprobación por
fragmento; backend y frontend los reensamblan por módulo, objetivo y fecha. Si
falta un fragmento, el estado pasa a `partial` y no se presenta como cobertura
completa.

## Dependencias, privacidad y licencia

El módulo reutiliza `requests`, ya presente en la imagen de SpiderFoot. Google
Public DNS no requiere API key y se describe como un servicio gratuito, pero no
ofrece SLA. Se envía `edns_client_subnet=0.0.0.0/0` para evitar remitir parte de la
IP del cliente a los servidores autoritativos. Las respuestas siguen siendo las
de un resolvedor recursivo y pueden provenir de caché.

En el equipo de validación Kaspersky inspecciona HTTPS. La primera consulta
falló con `CERTIFICATE_VERIFY_FAILED`; no se desactivó TLS. Compose monta
`deploy/spiderfoot-ca/` como solo lectura y el módulo acepta
`SPIDERFOOT_CA_BUNDLE`. El certificado raíz público local se exportó sin clave
privada, está ignorado por Git y se configuró únicamente en `spiderfoot.env`.
En otro entorno la variable debe quedar vacía o apuntar a la CA institucional
correspondiente.

El uso académico actual no elimina la obligación de revisar los términos. Antes
de una implementación comercial deben revisarse nuevamente los términos de las
APIs de Google, privacidad, límites operativos y requisitos de atribución vigentes;
no se documenta una licencia comercial implícita ni una garantía de disponibilidad.

Referencias oficiales:

- https://developers.google.com/speed/public-dns/docs/doh/json
- https://developers.google.com/speed/public-dns/docs/doh
- https://developers.google.com/speed/public-dns/faq
- https://developers.google.com/terms/

## Validación controlada

Las pruebas sintéticas cubren registros presentes, ausencia concluyente, error
parcial, falla total, TXT segmentado, filtros exactos, destinos externos,
DNSSEC, DKIM no verificable, normalización y el evaluador de `CONF-003` con la
regla activa e inactiva. La prueba del plugin confirma una sola ejecución por
objetivo y doce consultas DoH, sin seguir eventos de nombres vecinos.

La regresión final aprobó 239 pruebas backend y 2 subtests. En frontend pasaron
8 pruebas del reporte, ESLint, ambos proyectos TypeScript y el build Vite. El
build conserva el aviso previo por chunks JavaScript mayores de 500 kB; no está
relacionado con DNS DoH.

## Validación real autorizada

Antes de reconstruir se comprobó `ACTIVE_BAXTERSEC_SCANS=0`, cero scans activos
en SpiderFoot y el volumen `tc3008avjw_spiderfoot-data`. Solo se reconstruyeron
y recrearon `backend` y `spiderfoot`; el volumen se conservó. No se ejecutaron
migraciones, recálculos ni escrituras en Supabase.

La autorización vigente y el inventario confirmaron cuatro nombres. Se ejecutó
exclusivamente `sfp_baxter_dns_doh` contra cada uno, sin urlscan ni módulos de
IP:

| Activo exacto | Estado | A exactos | Observaciones | Problemas puntuables |
|---|---:|---|---:|---:|
| `receta-gastro-centro-app.vercel.app` | `ok` | `216.198.79.3`, `64.29.17.3` | 15 | 0 |
| `api.receta-gastro-centro-app.vercel.app` | `ok` | `216.198.79.3`, `64.29.17.3` | 15 | 0 |
| `dev.receta-gastro-centro-app.vercel.app` | `ok` | `64.29.17.67`, `216.198.79.67` | 15 | 0 |
| `www.receta-gastro-centro-app.vercel.app` | `ok` | `64.29.17.195`, `216.198.79.195` | 15 | 0 |

En los cuatro activos, A estuvo presente y AAAA, CNAME, MX, TXT, CAA, NS, SOA,
DS, MTA-STS y TLS-RPT exactos estuvieron ausentes en consultas concluyentes.
SPF no generó problema porque no había MX no nulo. DMARC quedó `unverified` por
posible herencia organizacional; DKIM, por falta de selector; DNSSEC, porque no
hubo `AD=true` ni DS exacto suficiente. Por tanto, cero problemas puntuables es
un resultado válido para esta evidencia y no una falla de ejecución.

Las 60 observaciones normalizadas quedaron vinculadas únicamente a sus cuatro
nombres. Las IP de Vercel se conservan dentro de los registros A, pero no se
crearon como activos ni objetivos. `CONF-003` se consultó en solo lectura y
continúa `esta_activa=false`, peso 10; no se creó ningún hallazgo ni se modificó
el Risk Score.

El verificador reproducible es `backend/tests/check_dns_doh_real.py`. No consulta
la base ni persiste resultados; exige que los objetivos se hayan autorizado y
emite un resumen por activo.
