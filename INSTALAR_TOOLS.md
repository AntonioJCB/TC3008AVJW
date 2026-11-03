# Instalar herramientas OSINT para BaxterSec

Guía para macOS y Linux; en Windows, ejecutar en WSL2 y correr también el backend
en WSL2. Las herramientas se instalan localmente en `tools/`, carpeta ignorada por
Git. No se deben subir sus entornos virtuales ni sus repositorios al proyecto.

## 1. Preparación

Requisitos: Git, Python 3.12 para el backend y SpiderFoot, Node.js compatible con
el frontend Next.js y npm. theHarvester usa otro entorno con Python 3.14.
En Linux pueden necesitarse compilador y cabeceras de Python para las dependencias.
En macOS, si una compilación lo requiere, instala las herramientas de Xcode con
`xcode-select --install`.

Abre una terminal nueva y entra a la raíz del clon de BaxterSec:

```bash
cd /ruta/a/TC3008AVJW
export BAXTERSEC_ROOT="$PWD"
mkdir -p "$BAXTERSEC_ROOT/tools"
```

`BAXTERSEC_ROOT` dura solo en esa terminal. En terminales nuevas vuelve a definirlo
desde la raíz del proyecto. No repitas `mkdir tools; cd tools` dentro de SpiderFoot:
eso crea carpetas anidadas por accidente.

Instala uv. En macOS con Homebrew:

```bash
brew install uv
uv --version
```

Para Linux y otras opciones, sigue la [instalación oficial de uv](https://docs.astral.sh/uv/getting-started/installation/).
Si ya tienes uv, no necesitas reinstalarlo. `install uv` no instala paquetes.

## 2. theHarvester

Estos comandos son para una instalación nueva. Si la carpeta ya existe, no la
borres: entra en ella y revisa su versión y cambios locales antes de actualizar.

```bash
git clone https://github.com/laramies/theHarvester.git "$BAXTERSEC_ROOT/tools/theHarvester"
cd "$BAXTERSEC_ROOT/tools/theHarvester"
git checkout 6790b147f52309e4eee22ed941db1d285ab2ec23
uv sync --locked
uv run theHarvester -h
```

El commit es el registrado originalmente por este proyecto. uv prepara su propio
entorno y Python según `.python-version`; no instales sus requisitos en el entorno
del backend. El aviso `detached HEAD` es normal al fijar una versión.

Desde esta misma carpeta prueba con un dominio propio o autorizado:

```bash
uv run theHarvester -d TU-DOMINIO.com -b crtsh -f /tmp/baxtersec-harvester
ls -lh /tmp/baxtersec-harvester*
```

El reporte puede ser `.json` o `.jsonl`, según la versión. El backend admite ambos.
Empieza con la fuente `crtsh`; revisa `-h` antes de agregar otras. Las llaves de
proveedores internos de theHarvester se configuran en su propio `api-keys.yaml`,
no automáticamente mediante el `.env` de BaxterSec. Consulta la documentación de
la versión instalada si necesitas fuentes con credenciales.

## 3. SpiderFoot v4.0

Desde la misma terminal, para una instalación nueva:

```bash
git clone --branch v4.0 --depth 1 https://github.com/smicallef/spiderfoot.git "$BAXTERSEC_ROOT/tools/spiderfoot"
cd "$BAXTERSEC_ROOT/tools/spiderfoot"
uv python install 3.12
uv venv --python 3.12 --seed .venv
.venv/bin/python -m pip install "setuptools<70" wheel "Cython<3"
.venv/bin/python -m pip install --no-build-isolation "PyYAML==5.4.1"
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -c "import yaml, cherrypy; print('Imports principales OK')"
```

Ejecuta cada comando por separado y detente si falla. No intentes arrancar el
servidor tras una instalación incompleta. La versión v4.0 corresponde al commit
`b9c345de5b085debc7444fc10e0e26e7745df5f2` registrado en este proyecto.

El paso especial de PyYAML evita el error `cython_sources` con las dependencias
antiguas de SpiderFoot. Véase la [explicación de PyYAML](https://github.com/yaml/pyyaml/issues/736).
Las dependencias transitivas no están completamente bloqueadas: otros sistemas o
versiones futuras de paquetes pueden requerir ajustes adicionales.

Arranca SpiderFoot y deja esta terminal abierta:

```bash
.venv/bin/python sf.py -l 127.0.0.1:5001
```

Abre http://127.0.0.1:5001. El backend usa este servidor por HTTP; no basta con tener
la carpeta descargada. El conector debe enviar `usecase=Passive` a la interfaz web
de v4.0; la comparación del nombre del grupo distingue mayúsculas.

## 4. Configurar BaxterSec

En otra terminal entra a la raíz del proyecto y prepara el backend con Python 3.12:

```bash
cd /ruta/a/TC3008AVJW
uv python install 3.12
uv venv --python 3.12 --seed backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt
```

Si ya existe `backend/.venv`, reutilízalo si corresponde a Python 3.12. No ejecutes
comandos para reemplazar entornos existentes sin revisar su contenido.

Si todavía no existe `backend/.env`, copia `backend/.env.example`. Si existe,
edítalo sin sobrescribirlo. Configura las variables OSINT:

```dotenv
THEHARVESTER_BIN=/RUTA/ABSOLUTA/TC3008AVJW/tools/theHarvester/.venv/bin/theHarvester
THEHARVESTER_SOURCES=crtsh
SPIDERFOOT_URL=http://127.0.0.1:5001
SHODAN_API_KEY=TU_LLAVE_SHODAN
```

Sustituye la ruta por la de tu computadora, sin usar la ruta personal de otro
compañero. Puedes obtenerla desde la raíz con:

```bash
pwd
```

`THEHARVESTER_BIN` debe contener solo la ruta al ejecutable, no `uv run ...`.
El backend lo ejecuta desde una carpeta temporal; por eso se usa una ruta absoluta.
crt.sh no requiere llave ni instalación adicional.

Para las credenciales de Supabase, la organización y las migraciones consulta
[LEEME_INTEGRACION.md](LEEME_INTEGRACION.md). Todos deben usar el mismo proyecto de
desarrollo acordado por el equipo. La llave pública va en el frontend; la llave
privilegiada permanece en el backend. El SDK Python fijado actualmente requiere
la llave JWT legacy `service_role`. Nunca subas archivos `.env` reales.

Shodan requiere permisos para `/dns/resolve` y `/shodan/host/{ip}`. Si responde
`Requires membership or higher to access`, la cuenta no tiene acceso al endpoint;
no se corrige reinstalando herramientas. El flujo puede continuar con riesgo
parcial si otras fuentes funcionan.

## 5. Arrancar y comprobar el flujo completo

Con SpiderFoot funcionando en la primera terminal, en la terminal del backend:

```bash
cd /ruta/a/TC3008AVJW/backend
.venv/bin/python -m app.check_supabase
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

`check_supabase` solo lee: no prueba escrituras ni las funciones RPC. Los tests
locales simulan proveedores y no demuestran que un dominio real fue consultado.
Evita editar código mientras corre un escaneo porque `--reload` lo interrumpe.

En una tercera terminal:

```bash
cd /ruta/a/TC3008AVJW/frontend-next
npm install
npm run typecheck
npm run dev
```

Antes de iniciar, configura `frontend-next/.env.local` a partir de la plantilla:

```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_SUPABASE_URL=https://TU-PROYECTO.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_TU_LLAVE_PUBLICA
```

Abre http://localhost:3000, regístrate o inicia sesión y prepara la organización y
autorización según la guía de integración. Crea un escaneo de un dominio autorizado.
El frontend envía el token de sesión automáticamente y consulta el avance.

Conserva el UUID de la URL `/escaneos/UUID` y búscalo en Supabase Table Editor:

| Tabla | Filtro | Qué confirma |
|---|---|---|
| escaneos | id = UUID | Creación y estado persistidos |
| resultados_fuentes | escaneo_id = UUID | Estado y error de cada fuente |
| resultados_crudos | escaneo_id = UUID | Respuestas externas guardadas |
| observaciones | escaneo_id = UUID | Hechos normalizados, si hubo datos utilizables |
| hallazgos | escaneo_id = UUID | Coincidencias con reglas, si existen |
| puntajes_riesgo | escaneo_id = UUID | Puntaje y cobertura guardados |

Si Shodan falla y las demás funcionan, el estado esperado es `incompleto` y el
riesgo es parcial. Cero resultados no implica un fallo: revisa crudos, contadores
y descartes. Los hallazgos pueden estar vacíos aunque la persistencia funcione.
Una IP compartida de alojamiento no debe atribuirse automáticamente a tu aplicación.

## 6. Mantener tools fuera de Git

Desde la raíz:

```bash
git ls-files tools
git check-ignore tools/spiderfoot tools/theHarvester
```

El primer comando no debe listar nada; el segundo debe mostrar las rutas ignoradas.
Comparte esta guía, las plantillas de configuración y el código de BaxterSec.
Cada compañero instala sus herramientas localmente.
