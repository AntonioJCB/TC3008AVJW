# Puesta en marcha de fuentes OSINT

El backend ejecuta cuatro adaptadores pasivos: crt.sh, Censys, theHarvester y SpiderFoot. Web es una validación activa opcional con habilitación del servidor y consentimiento explícito por análisis.
Un resultado `completado` con cero observaciones significa que la consulta terminó sin evidencia normalizable; revisa el crudo y los descartes antes de concluir que no encontró datos.
`incompleto` significa que alguna fuente falló; `fallido`, que ninguna terminó.
Los escaneos de prueba con IP `203.0.113.x` usan direcciones reservadas para
documentación y no demuestran conectividad real de los proveedores.

## Comprobación local en Windows

Desde la raíz del repositorio en PowerShell:

```powershell
cd .\backend
Get-Command theHarvester -ErrorAction SilentlyContinue
Test-NetConnection 127.0.0.1 -Port 5001
.\.venv\Scripts\python.exe -m pytest -q tests/test_collectors.py
```

| Fuente | Requisito | Fallo frecuente | Acción |
| --- | --- | --- | --- |
| crt.sh | Acceso HTTPS a `crt.sh` | `ReadTimeout`, HTTP 429 o 502/504 | Hasta cuatro intentos con espera creciente; respeta `Retry-After` en HTTP 429 y espera 30 s cuando falta esa cabecera. Ajusta `CRTSH_TIMEOUT_SECONDS` si la red es lenta. Si crt.sh sigue caído, la fuente queda fallida para no presentar datos incompletos como cobertura sana. |
| Censys | PAT Platform v3 y créditos para lookup de hosts | HTTP 401, 403, 429 | Configura `CENSYS_PAT`, revisa permisos/cuota; usa [la guía Censys](censys.md). DNS se resuelve localmente, sin buscador de pago. |
| theHarvester | Ejecutable instalado en el mismo sistema donde corre FastAPI | `THEHARVESTER_BIN` apunta a otro equipo o el programa no está en `PATH` | Instala theHarvester por separado y fija `THEHARVESTER_BIN` a un ejecutable local. Por defecto consulta `certspotter,hackertarget`; comprueba `THEHARVESTER_SOURCES` en el `.env` real. |
| theHarvester | Ejecutable instalado en el mismo sistema donde corre FastAPI | `THEHARVESTER_BIN` inválido o cuota de un proveedor agotada | Por defecto consulta `certspotter,rapiddns,urlscan`; comprueba `THEHARVESTER_SOURCES` en el `.env` real. Cada proveedor conserva su estado y procedencia en el JSONL guardado. |
| SpiderFoot | Servidor web activo en `SPIDERFOOT_URL` | `ConnectError`, tiempo máximo o cancelación | Inicia SpiderFoot antes del análisis y verifica la URL desde FastAPI. El backend usa los módulos de `SPIDERFOOT_MODULES` para acotar la duración; el grupo `Passive` completo puede ejecutar módulos lentos o defectuosos. Una cancelación solicita detener también el trabajo remoto. |
| Web | `WEB_ENABLED=true` y consentimiento por análisis | La petición `HEAD /` y la negociación TLS son activas | Solo FQDN principal autorizado en 80/443. Sin conclusión no produce hallazgos. |

### Qué puede comprobar crt.sh

crt.sh consulta los registros públicos de Certificate Transparency. En cada
análisis busca `%.dominio-autorizado` para cubrir los subdominios del inventario
y los que aún no se conocen, y también el nombre exacto del dominio principal.
Si falla la búsqueda de sufijo, intenta los nombres autorizados ya registrados
por separado. No consulta IPs ni prueba servicios de red. Una búsqueda de sufijo
correcta evita las consultas redundantes de cada subdominio.

El resultado crudo conserva las consultas efectuadas, fecha, estado, errores y
número de registros recibidos, junto con los objetivos cubiertos. El registro
de crt.sh en **Fuentes** muestra además las observaciones guardadas, activos y
hallazgos atribuibles a esta fuente. Los nombres fuera del dominio autorizado
se descartan; los certificados repetidos se consolidan como observaciones. Un
HTTP 200 sin cuerpo, JSON inválido o error del proveedor no se presenta como
una búsqueda vacía válida. Si una consulta tuvo éxito y otra falló, el resultado
se conserva con incidencia; si ninguna tuvo éxito, la fuente falla sin borrar
los resultados de las otras fuentes.
Al guardar el resultado crudo, los cortes transitorios de conexión con Supabase
se reintentan sobre una escritura idempotente; si la respuesta se pierde después
del commit, se recupera la fila existente por escaneo, fuente y hash. Si se
agotan los reintentos, el estado indica un error de persistencia y no atribuye
el fallo a la consulta de crt.sh.

Un certificado de CT es **histórico**: demuestra que se emitió para un nombre,
pero no que ese nombre resuelva hoy, que el certificado siga instalado o que
haya una vulnerabilidad. La información del certificado queda asociada a cada
activo del inventario, pero no comprueba el estado TLS servido hoy. Encontrar
certificados o nuevos subdominios no eleva automáticamente el Risk Score. Las
reglas CONF-001/002 conservan peso cero y están inactivas tras retirar Web,
pues dependían de una comprobación TLS activa. En plataformas
compartidas como `vercel.app`, la búsqueda de un
subdominio de cliente puede no devolver registros propios aunque el sitio tenga
HTTPS: el certificado puede pertenecer al proveedor.

Cert Spotter completó una consulta válida y en otra devolvió `invalid-response`;
RapidDNS y urlscan completaron sin registros para el dominio de prueba.
Un resultado `completado`
con cero observaciones puede ser correcto para un subdominio alojado en una
plataforma compartida. HackerTarget agotó la cuota anónima, OTX respondió
HTTP 429 y Common Crawl agotó su límite de ejecución; por eso no están en
la configuración inicial.
Si un proveedor falla, el desglose conserva su estado y cualquier dato obtenido
por los demás. La fuente se muestra parcial cuando hay incidencias internas.
Los hallazgos requieren una regla activa y evidencia suficiente; descubrir un
nombre o una IP compartida no aumenta por sí solo el Risk Score.

El perfil predeterminado conserva `sfp_dnsresolve`, `sfp_dnsraw`, `sfp_robtex`
y `sfp_crobat_api`, y añade `sfp_baxter_dns_doh` y `sfp_baxter_urlscan`.
DNS DoH consulta A, AAAA, CNAME, MX, TXT, CAA, NS, SOA, DS, DMARC, MTA-STS y
TLS-RPT del nombre exacto, separa ausencias de errores y no convierte destinos
de proveedores en activos. urlscan busca únicamente análisis ya publicados
para el nombre exacto y no solicita un nuevo escaneo.
La respuesta conserva proveedor, módulo, consulta, fecha, estado y limitaciones.
Los módulos DNS hacen consultas DNS o a proveedores públicos; ninguno visita el
sitio web ni comprueba puertos o servicios.

El módulo `sfp_baxter_internetdb` fue retirado de la imagen actual. La variable
`SPIDERFOOT_INTERNETDB_USE` no lo habilita; haría falta una implementación revisada.
Una respuesta HTTP fallida o un resultado truncado se registra como limitación y
nunca como cero válido.

El backend rechaza cualquier nombre de módulo fuera de este perfil revisado.
Esto impide habilitar accidentalmente `sfp_spider`, Nuclei, RetireJS u otros
módulos que contactan al objetivo. Los módulos DNS anteriores y el perfil previo
se reconocen como configuración heredada y se amplían automáticamente con DNS
DoH y urlscan al arrancar el backend.

Web usa `asyncio`, `socket` y `ssl` para comprobar el FQDN principal autorizado.
La evidencia nueva se marca como comprobación activa; observaciones antiguas no
se convierten en confirmaciones al recalcular. Las reglas CONF-006/007/008
respetan su estado y peso actuales en el catálogo. El análisis pasivo sigue
sujeto a `SCAN_MAX_TARGETS`.

Los cambios de `.env` requieren reiniciar Uvicorn. El valor de
`THEHARVESTER_BIN` es una ruta del **equipo que ejecuta FastAPI**; una ruta
`/Users/...` de macOS no funciona en Windows. theHarvester y SpiderFoot no
forman parte de las dependencias de `backend/pyproject.toml`.

Enlace a las instrucciones oficiales: [theHarvester](https://github.com/laramies/theHarvester/blob/master/docs/wiki/Installation.md),
[SpiderFoot](https://github.com/smicallef/spiderfoot/blob/master/Dockerfile) y
[API de Censys Platform](https://docs.censys.com/reference/get-started).
