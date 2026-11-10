# Puesta en marcha de fuentes OSINT

El backend ejecuta cuatro adaptadores independientes. Un resultado `completado`
con cero observaciones significa que la consulta terminó, pero no encontró datos.
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
| Shodan | Clave con acceso a `/dns/resolve` y `/shodan/host/{ip}` | HTTP 403 con `Requires membership or higher` | La clave puede ser válida y el plan insuficiente. Revisa el plan en `/api-info` y el acceso de la cuenta; no sirve cambiar de llave pública de Supabase. |
| theHarvester | Ejecutable instalado en el mismo sistema donde corre FastAPI | `THEHARVESTER_BIN` apunta a otro equipo o el programa no está en `PATH` | Instala theHarvester por separado y fija `THEHARVESTER_BIN` a un ejecutable local. Por defecto consulta `certspotter,hackertarget`; comprueba `THEHARVESTER_SOURCES` en el `.env` real. |
| SpiderFoot | Servidor web activo en `SPIDERFOOT_URL` | `ConnectError`, tiempo máximo o cancelación | Inicia SpiderFoot antes del análisis y verifica la URL desde FastAPI. El backend usa los módulos de `SPIDERFOOT_MODULES` para acotar la duración; el grupo `Passive` completo puede ejecutar módulos lentos o defectuosos. Una cancelación solicita detener también el trabajo remoto. |

Cert Spotter permite consultas anónimas limitadas para evaluación. Antes de
usar este proveedor con tráfico de producción, hay que contratar/configurar
acceso a su API y conservar su procedencia de forma explícita; el modo de
theHarvester aquí sirve para las pruebas actuales. Un resultado `completado`
con cero observaciones puede ser correcto para un subdominio alojado en una
plataforma compartida.
HackerTarget también puede aportar IPs, aunque las IPs de una plataforma
compartida no prueban riesgos propios de la organización. Si alguna de las
fuentes configuradas limita la consulta, el backend reporta theHarvester como fallido
en vez de considerar completa una respuesta vacía.

Por defecto, `SPIDERFOOT_MODULES` incluye `sfp_dnsresolve`, `sfp_dnsraw`,
`sfp_robtex` y `sfp_crobat_api`. Son módulos pasivos sin llave en la versión
fijada por `deploy/spiderfoot.Dockerfile`; aportan dominios e IPs que el backend
puede normalizar. Si se cambia la versión de SpiderFoot, comprueba que aún
existen. La lista se puede ajustar en `backend/.env` sin cambiar el código.
El módulo `sfp_stevenblack_hosts` queda fuera porque la versión fijada lanza
`IndexError` al procesar algunas líneas de su lista externa.

Los cambios de `.env` requieren reiniciar Uvicorn. El valor de
`THEHARVESTER_BIN` es una ruta del **equipo que ejecuta FastAPI**; una ruta
`/Users/...` de macOS no funciona en Windows. theHarvester y SpiderFoot no
forman parte de las dependencias de `backend/pyproject.toml`.

Enlace a las instrucciones oficiales: [theHarvester](https://github.com/laramies/theHarvester/blob/master/docs/wiki/Installation.md),
[SpiderFoot](https://github.com/smicallef/spiderfoot/blob/master/Dockerfile) y
[API de Shodan](https://developer.shodan.io/api).
