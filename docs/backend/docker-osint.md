# Backend y herramientas OSINT con Docker Compose

Esta configuración es para desarrollo compartido. Construye una imagen del
backend que incluye el ejecutable de theHarvester y otra imagen para el servicio
web de SpiderFoot. crt.sh y Shodan se consultan por HTTPS; Supabase sigue siendo
externo. No hace falta clonar las herramientas en `backend/` ni instalarlas en
Windows: los Dockerfiles las descargan en commits fijos durante la construcción.

## 1. Preparar Docker y la configuración

Instala y abre Docker Desktop en modo contenedores Linux. Desde la raíz del
repositorio, comprueba que el motor responde:

```powershell
docker version
docker compose version
```

Si `docker version` indica que no encuentra
`dockerDesktopLinuxEngine`, abre Docker Desktop y espera a que termine de
iniciar. `docker compose config` funciona sin el motor, pero `build` y `up` no.

Configura `backend/.env` a partir de `backend/.env.example` si aún no existe.
Necesitas `SUPABASE_URL` y `SUPABASE_SERVICE_ROLE_KEY` del mismo proyecto. La
clave de Shodan es opcional; la cuenta debe tener acceso a las rutas DNS y host
para que esa fuente funcione. El archivo `.env` no debe subirse a Git.

Compose establece dentro del contenedor las dos rutas que cambian respecto a
Windows:

```text
THEHARVESTER_BIN=/opt/theHarvester/.venv/bin/theHarvester
SPIDERFOOT_URL=http://spiderfoot:5001
```

Una ruta local `C:\...` en `.env` no se usa dentro del contenedor. El nombre
`spiderfoot` se resuelve en la red interna de Compose.

## 2. Construir e iniciar

Ejecuta estos comandos en PowerShell, desde la raíz del repositorio:

```powershell
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

El primer `build` descarga Python, dependencias y ambos repositorios OSINT;
puede tardar varios minutos. Los Dockerfiles fijan el commit del código de
theHarvester y SpiderFoot. Las dependencias del backend y de SpiderFoot aún se
resuelven desde rangos de versión, por lo que falta un lockfile propio para un
build plenamente reproducible.

## 3. Comprobar cada pieza

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Test-NetConnection 127.0.0.1 -Port 5001
docker compose exec backend /opt/theHarvester/.venv/bin/theHarvester -h
docker compose exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://spiderfoot:5001/', timeout=5).status)"
docker compose logs --tail=80 backend spiderfoot
```

La ruta `/health` confirma que FastAPI responde. El puerto 5001 y la consulta
desde `backend` confirman que SpiderFoot escucha y es alcanzable en la red
interna. `theHarvester -h` confirma que el ejecutable quedó instalado. Ninguna
de estas comprobaciones demuestra que crt.sh o la cuenta de Shodan respondan.

En el navegador, la API estará en `http://127.0.0.1:8000/docs` y la interfaz
local de SpiderFoot en `http://127.0.0.1:5001/`. Ejecuta un escaneo desde el
portal solo con un dominio autorizado; consulta su estado por fuente para ver
cuáles completaron y qué devolvieron.

## 4. Diagnóstico y operación

```powershell
docker compose ps
docker compose logs --tail=150 backend
docker compose logs --tail=150 spiderfoot
docker compose down
```

`docker compose down` detiene los servicios. Los datos de SpiderFoot permanecen
en el volumen `spiderfoot-data`. No uses `down -v` si quieres conservarlos.

Si Shodan devuelve 403 con `Requires membership`, la instalación del contenedor
está bien; revisa el plan de la cuenta. Un `ReadTimeout` de crt.sh puede ocurrir
aunque la red del contenedor funcione. Consulta [osint.md](osint.md) para el
diagnóstico de cada fuente.

## Antes de publicar

Los puertos de Compose están vinculados a `127.0.0.1` para desarrollo. En un
servidor se necesita entrada HTTPS controlada para el backend, manejo de
secretos, almacenamiento persistente para SpiderFoot y una cola de trabajos
persistente para los análisis. La versión actual ejecuta trabajos dentro del
proceso FastAPI; un reinicio puede interrumpirlos. No expongas el puerto 5001
de SpiderFoot directamente a Internet.
