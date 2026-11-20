# Validación real del perfil pasivo SpiderFoot

Fecha de ejecución: 18 de noviembre de 2026 (America/Mexico_City; registros UTC del 19 de noviembre).

## Alcance y controles previos

- Organización: `Gastrocentro-demo`.
- Dominio autorizado: `receta-gastro-centro-app.vercel.app`.
- La autorización vigente cubría el dominio y sus subdominios; no cubría las IP compartidas del proveedor.
- Antes de reconstruir no había escaneos en estado `ejecutando` ni en Supabase ni en SpiderFoot.
- Solo se reconstruyeron y recrearon `backend` y `spiderfoot`.
- Se conservó el volumen `tc3008avjw_spiderfoot-data`. SpiderFoot tenía 67 escaneos antes de la validación y 75 después de dos ejecuciones de cuatro objetivos.
- No se ejecutaron migraciones, recálculos históricos ni cambios manuales de datos.

## Configuración validada

Perfil efectivo:

```text
sfp_dnsresolve
sfp_dnsraw
sfp_robtex
sfp_crobat_api
sfp_baxter_urlscan
```

El perfil conserva los cuatro módulos DNS anteriores y añade `sfp_baxter_urlscan`. InternetDB y Shodan permanecen deshabilitados.

## Análisis de validación

La primera ejecución utilizó el escaneo pendiente autorizado `3a54e795-67aa-4195-99c7-858ffb4d8938`. Esa corrida demostró que SpiderFoot exportaba cuatro semillas de `SpiderFoot UI` y el normalizador las trataba como observaciones. Se corrigió la exclusión de eventos internos, se reconstruyeron nuevamente ambos contenedores y se repitió la validación. El análisis siguiente es la ejecución final de referencia.

- ID: `03373df2-1777-4571-a785-61c50ab90b54`.
- Estado: `completado`.
- Inicio: `2026-11-19T04:26:28.514577+00:00`.
- Fin: `2026-11-19T04:27:29.829281+00:00`.
- Duración aproximada: 61 segundos.
- Motor de riesgo: `1.3.2`.

Los cuatro objetivos autorizados se consultaron con crt.sh, SpiderFoot y theHarvester:

1. `receta-gastro-centro-app.vercel.app`
2. `api.receta-gastro-centro-app.vercel.app`
3. `dev.receta-gastro-centro-app.vercel.app`
4. `www.receta-gastro-centro-app.vercel.app`

## Resultados por fuente

### SpiderFoot

- Estado persistido: `completado`, sin error.
- Exportación cruda: 425 eventos.
- Eventos por módulo: `sfp_dnsresolve` 151, `sfp_dnsraw` 52, `sfp_robtex` 214, `sfp_baxter_urlscan` 4 y `SpiderFoot UI` 4.
- `sfp_crobat_api` estuvo seleccionado pero no emitió eventos para estos objetivos.
- urlscan respondió HTTP 200 para los cuatro objetivos. Las cuatro consultas quedaron en estado `empty`, con cero resultados en el historial público de 90 días.
- Se generaron 12 observaciones normalizadas: 4 `descubierto` y 8 `resuelve_a`, todas atribuibles a `sfp_dnsresolve`.
- Se descartaron 409 eventos de tipos no soportados y 4 eventos internos de `SpiderFoot UI`.
- Los cuatro eventos internos ya no se presentan como evidencia de proveedor ni como activos descubiertos.

Los eventos no soportados incluyen principalmente relaciones de cohosting, afiliados y datos DNS crudos. Se conservan en el resultado crudo para detalle técnico, pero no activan reglas ni se convierten automáticamente en riesgo.

### crt.sh

- Estado persistido: `completado`, sin error.
- Se ejecutaron la consulta exacta y la consulta con sufijo para el dominio autorizado.
- Ambas consultas respondieron correctamente y devolvieron cero certificados.
- El reporte registra expresamente los cuatro objetivos como cubiertos; cero resultados no se interpreta como falla ni como prueba de ausencia de riesgo.

### theHarvester

- Estado persistido: `completado`, sin error.
- Cuatro ejecuciones, una por objetivo autorizado.
- `certspotter`, `rapiddns` y `urlscan` terminaron en cada ejecución.
- Los 12 proveedores terminaron con `no-results`; se obtuvieron cero hosts, IP, correos, ASN y vhosts.

## Persistencia, normalización y riesgo

- Las tres fuentes conservaron un `resultado_crudo_id` en Supabase.
- SpiderFoot persistió 12 observaciones nuevas, sin duplicados y relacionadas con los activos correspondientes.
- No se crearon hallazgos.
- Risk Score global y por categoría: 0.
- Se evaluaron las cuatro reglas activas: `IDEN-003`, `INFRA-001`, `INFRA-002` e `INFRA-003`.
- Las otras 15 reglas del catálogo estaban inactivas; no se alteraron reglas ni pesos.

El puntaje cero es coherente con la evidencia recibida: hubo resolución y descubrimiento DNS, pero no hubo banners, servicios expuestos, CVE verificadas, certificados vencidos ni otra observación que cumpliera una regla activa. A la vez, el resultado no demuestra ausencia de vulnerabilidades: urlscan no tenía registros para esos nombres y las IP relacionadas no estaban autorizadas para consulta como objetivos independientes.

## Cobertura y limitaciones

El inventario contenía 18 activos:

- 4 dominios/subdominios autorizados y consultados por las tres fuentes.
- 12 IP/servicios no evaluados porque la autorización del dominio no autoriza las IP compartidas del proveedor ni servicios asociados a una IP ajena al alcance.
- 2 correos sin consulta compatible en el perfil configurado.

Por lo anterior, `es_parcial=true` y `cobertura_incompleta=true` son correctos aunque las tres fuentes hayan terminado: describen la cobertura del inventario, no un fallo de ejecución.

## Comparación antes/después

| Aspecto | Antes (`8e393528-...`) | Después (`03373df2-...`) |
|---|---:|---:|
| Estado del análisis | Incompleto | Completado |
| Objetivos autorizados consultados | 4 | 4 |
| Módulos DNS con eventos | dnsresolve, dnsraw, robtex | dnsresolve, dnsraw, robtex |
| urlscan propio de Baxter | No | Sí, 4 consultas HTTP 200 |
| Observaciones SpiderFoot | 18 | 12 |
| Eventos internos contados como evidencia | 4 | 0 |
| Incidencias crt.sh | HTTP 404 registrado | Ninguna; 2 consultas válidas con cero resultados |
| Incidencias theHarvester | rate limit de certspotter | Ninguna; 12 ejecuciones de proveedor completas |
| Hallazgos | 0 | 0 |
| Risk Score | 0, parcial | 0, parcial |

La reducción de 18 a 12 observaciones no es pérdida de cobertura DNS: elimina cuatro semillas internas y, en la consulta nueva, DNS devolvió cuatro IP actuales en vez de las seis IP observadas en la ejecución anterior. La capacidad se amplió con urlscan, pero esta organización no produjo evidencia nueva de seguridad en esa fuente.

## Pruebas y estado operativo

- Backend: 232 pruebas y 2 subpruebas aprobadas; 2 advertencias de dependencias.
- Frontend: 5 pruebas aprobadas.
- TypeScript de aplicación y configuración Node: sin errores.
- ESLint: sin errores.
- Build de producción Vite: generado correctamente; conserva la advertencia no bloqueante por chunks mayores a 500 kB.
- `backend` y `spiderfoot`: saludables después de la validación.
- Escaneos activos al cierre: 0.

## Pendiente de despliegue y capacidades no habilitadas

- Los cambios están activos en los contenedores locales reconstruidos. No se desplegaron a otro entorno.
- El frontend no forma parte de Compose; sus mejoras de reporte requieren reiniciar o desplegar la aplicación Vite que corresponda.
- InternetDB sigue deshabilitado hasta confirmar que el uso cumple sus condiciones no comerciales o exista licencia aplicable.
- Shodan Host sigue deshabilitado sin API key/licencia válida.
- Sin una fuente pasiva de IP autorizada y sin autorización explícita de esas IP, el perfil no puede afirmar servicios, versiones o vulnerabilidades para la infraestructura compartida de Vercel.
