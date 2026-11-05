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
| crt.sh | Acceso HTTPS a `crt.sh` | `ReadTimeout` o HTTP 502/504 | Reintentos automáticos. Ajusta `CRTSH_TIMEOUT_SECONDS` si la red es lenta. Una caída del proveedor puede seguir causando fallo. |
| Shodan | Clave con acceso a `/dns/resolve` y `/shodan/host/{ip}` | HTTP 403 con `Requires membership or higher` | La clave puede ser válida y el plan insuficiente. Revisa el plan en `/api-info` y el acceso de la cuenta; no sirve cambiar de llave pública de Supabase. |
| theHarvester | Ejecutable instalado en el mismo sistema donde corre FastAPI | `THEHARVESTER_BIN` apunta a otro equipo o el programa no está en `PATH` | Instala theHarvester por separado y fija `THEHARVESTER_BIN` a un ejecutable local. Comprueba `Get-Command theHarvester`. |
| SpiderFoot | Servidor web activo en `SPIDERFOOT_URL` | `ConnectError` a `127.0.0.1:5001` | Inicia SpiderFoot antes del backend/escaneo y verifica el puerto. Si corre en Docker o en otra máquina, publica el puerto y configura la URL accesible desde FastAPI. |

Los cambios de `.env` requieren reiniciar Uvicorn. El valor de
`THEHARVESTER_BIN` es una ruta del **equipo que ejecuta FastAPI**; una ruta
`/Users/...` de macOS no funciona en Windows. theHarvester y SpiderFoot no
forman parte de las dependencias de `backend/pyproject.toml`.

Enlace a las instrucciones oficiales: [theHarvester](https://github.com/laramies/theHarvester/blob/master/docs/wiki/Installation.md),
[SpiderFoot](https://github.com/smicallef/spiderfoot/blob/master/Dockerfile) y
[API de Shodan](https://developer.shodan.io/api).
