# BaxterSec

Plataforma OSINT para descubrir, organizar y visualizar información pública relacionada con la superficie de exposición de un dominio autorizado.

> Proyecto académico en desarrollo. Sólo se utilizarán fuentes públicas, APIs autorizadas y técnicas pasivas de recopilación.

## Objetivo

Construir una aplicación que permita:

- Analizar un dominio autorizado.
- Recopilar información desde diferentes fuentes OSINT.
- Normalizar y deduplicar los resultados.
- Identificar activos y posibles hallazgos.
- Calcular un nivel de riesgo trazable.
- Consultar los resultados mediante un dashboard.

## Tecnologías

- **Frontend:** React, Vite y TypeScript.
- **Backend:** Python y FastAPI.
- **Base de datos y autenticación:** Supabase (PostgreSQL y Auth).
- **Entorno de desarrollo:** Docker y Docker Compose.
- **Despliegue del frontend:** Vercel.

## Estructura

```text
TC3008AVJW/
├── backend/     # API, orquestación y procesamiento
├── frontend/    # Dashboard web
├── database/    # Migraciones y recursos de Supabase
├── deploy/      # Dockerfiles del backend y SpiderFoot
└── compose.yaml # Servicios locales de Docker Compose
```

## Flujo de ramas

- main: versión estable y conectada a producción.
- dev: integración y pruebas antes de producción.
- feature/\*: desarrollo de nuevas funcionalidades.
- fix/_: corrección de errores.
  Los cambios deben enviarse mediante Pull Request:
  feature/_ → dev → main
  Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para conocer las reglas de colaboración.

## Estado del proyecto

La API de escaneos FastAPI está en [backend/](backend/README.md). El login, la administración y el portal de cliente usan Supabase Auth y RLS. El portal permite crear, ejecutar y detener análisis autorizados; muestra el avance por fuente y consulta resultados reales.

## Documentación

La documentación por componente está en [docs/README.md](docs/README.md): [backend](docs/backend/README.md), [base de datos](docs/database/README.md) y [frontend](docs/frontend/README.md).

## Manual de instalación y ejecución local

La ruta recomendada para desarrollo usa **Docker Compose** para FastAPI,
theHarvester y SpiderFoot, **Vite** para React y un proyecto **Supabase** para
PostgreSQL y Auth. Compose no crea el proyecto Supabase ni inicia el frontend.
Los comandos siguientes están escritos para PowerShell y se ejecutan desde la
raíz del repositorio, salvo cuando se indica otro directorio.

### Requisitos

- Git y conexión a Internet para obtener el código y construir las imágenes.
- Docker Desktop abierto en modo contenedores Linux, con `docker compose`
  disponible. Compruébalo con `docker version` y `docker compose version`.
- Node.js **20.19 o posterior de la serie 20**, o **22.12 o posterior**, y npm.
  Son los rangos admitidos por la versión de Vite del frontend. Compruébalo
  con `node --version` y `npm --version`.
- Un proyecto Supabase al que tengas acceso, nuevo o ya preparado por el equipo.
  Su URL y sus claves deben corresponder al mismo proyecto.
- Puertos locales `8000`, `5001` y, por defecto, `5173` disponibles.

No necesitas instalar Python, PostgreSQL, theHarvester ni SpiderFoot en Windows
si sigues esta ruta. Para ejecutar el backend sin Docker, consulta
[backend/README.md](backend/README.md).

### 1. Obtener el código

```powershell
git clone https://github.com/AntonioJCB/TC3008AVJW.git
cd TC3008AVJW
```

Si ya tienes el repositorio, entra en su raíz. Usa una versión que contenga
`compose.yaml`, `backend/.env.example` y `frontend/package-lock.json`.

### 2. Preparar Supabase

**Base compartida del equipo:** confirma con el responsable que ya están
aplicadas las migraciones y el catálogo de `database/supabase/seed.sql`. No
ejecutes `db push` ni el seed sobre ella como parte de una instalación local.

**Proyecto nuevo y aislado:** créalo en Supabase y, desde `database/`, instala
la CLI incluida en el proyecto, enlaza el proyecto correcto y revisa las
migraciones antes de aplicarlas:

```powershell
cd database
npm install
npx supabase login
npx supabase link --project-ref TU_PROJECT_REF
npx supabase db push --dry-run --remote
npx supabase db push --include-seed --remote
cd ..
```

Sustituye `TU_PROJECT_REF` por el identificador de tu proyecto. La CLI puede
pedir la contraseña de la base de datos. `--include-seed` carga las fuentes
OSINT y reglas iniciales después de las migraciones. Si el proyecto ya tiene
datos o un historial de migraciones distinto, revisa primero la
[guía de base de datos](docs/database/README.md); no apliques la migración base
sobre un esquema existente sin compararlo. Consulta también la
[guía oficial de migraciones de Supabase](https://supabase.com/docs/guides/deployment/database-migrations).

En **Supabase Auth → URL Configuration**, configura la URL local del frontend
(`http://localhost:5173`) y permite la redirección
`http://localhost:5173/restablecer-clave` para invitaciones y recuperación de
contraseña. Si Vite usa otro puerto, actualiza esas URL y `FRONTEND_URL`.

### 3. Configurar variables de entorno

Copia las plantillas solo si todavía no tienes los archivos `.env`:

```powershell
if (-not (Test-Path backend/.env)) { Copy-Item backend/.env.example backend/.env }
if (-not (Test-Path frontend/.env)) { Copy-Item frontend/.env.example frontend/.env }
```

Edita ambos archivos y sustituye los valores de ejemplo:

| Archivo         | Variable                        | Valor                                                                                                         |
| --------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `backend/.env`  | `SUPABASE_URL`                  | URL del proyecto Supabase.                                                                                    |
| `backend/.env`  | `SUPABASE_SERVICE_ROLE_KEY`     | Llave **legacy service_role** del mismo proyecto, solo para el servidor. Esta versión no acepta `sb_secret_`. |
| `backend/.env`  | `FRONTEND_URL`                  | Dirección de Vite; por defecto `http://localhost:5173`.                                                       |
| `frontend/.env` | `VITE_SUPABASE_URL`             | La misma URL de Supabase.                                                                                     |
| `frontend/.env` | `VITE_SUPABASE_PUBLISHABLE_KEY` | Llave publicable del mismo proyecto.                                                                          |
| `frontend/.env` | `VITE_API_URL`                  | `http://localhost:8000` para esta instalación.                                                                |

### 4. Iniciar y comprobar la API

Abre Docker Desktop y ejecuta desde la raíz:

```powershell
docker compose config --quiet
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
```

`backend` y `spiderfoot` deben aparecer como `healthy`; `/health` debe devolver
`{"estado":"disponible"}`. La primera construcción descarga dependencias y
puede tardar varios minutos. La documentación OpenAPI queda en
<http://127.0.0.1:8000/docs>. La ruta `/health` solo confirma que el proceso
responde; el acceso a Supabase se comprueba al iniciar sesión y consultar datos.

### 5. Iniciar el frontend

En **otra terminal** de PowerShell, desde la raíz:

```powershell
cd frontend
npm install
npm run dev
```

Abre la URL que muestre Vite, normalmente <http://localhost:5173>. Conserva
ambas terminales y Docker Desktop activos mientras uses la aplicación.

### 6. Verificar el acceso y un análisis autorizado

En un proyecto Supabase nuevo, crea primero una cuenta en **Authentication →
Users**; la migración de Auth crea su perfil en `public.usuarios`. Para que
administre la plataforma, asígnale la membresía mediante el procedimiento de
la [guía de base de datos](docs/database/README.md). Esa membresía no se
concede desde el frontend. Después inicia sesión en `/login`. El administrador
de plataforma puede crear un cliente e invitar usuarios desde `/admin`.

Para entrar al portal cliente, la cuenta debe estar activa y vinculada a una
organización. Antes de iniciar un análisis debe existir una autorización
vigente que incluya el dominio principal de esa organización. Usa solo un
dominio propio o expresamente autorizado. Comprueba que `/home` muestra datos
del cliente y que el estado del análisis informa el resultado de cada fuente.

### 7. Reiniciar, diagnosticar y detener

Tras la primera instalación, `docker compose up -d` inicia los contenedores
sin reconstruirlos; inicia Vite otra vez con `npm run dev` desde `frontend/`.
Para revisar problemas, desde la raíz:

```powershell
docker compose ps
docker compose logs --tail=100 backend spiderfoot
```

Si Docker no encuentra `dockerDesktopLinuxEngine`, abre Docker Desktop y
espera a que arranque. Si el navegador no carga el portal, confirma la URL
mostrada por Vite y las variables `VITE_*`. Si el login funciona pero el portal
no muestra datos, comprueba el perfil, la organización y las políticas RLS de
Supabase. Un 403 de Shodan puede indicar que el plan de la cuenta no permite
las consultas requeridas. Para diagnóstico de fuentes consulta la
[guía de Docker y OSINT](docs/backend/docker-osint.md).

Detén Vite con `Ctrl+C` en su terminal y los contenedores con `docker compose
down` desde la raíz. El volumen de SpiderFoot se conserva; evita `down -v` si
quieres mantener sus datos.

## Equipo

- Antonio Jesús Calderón Burgos
- Jaime Gámez Gómez-Rubalcava
- Valeria Pérez Mendoza
- Willian Salomon Lemus Sanchez

## Aviso de uso

Este proyecto está diseñado exclusivamente para fines académicos y defensivos. Los análisis deben realizarse únicamente sobre dominios propios, ficticios o expresamente autorizados.
