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

## Instalación y ejecución local

Estas instrucciones usan Docker Compose para el backend, theHarvester y
SpiderFoot, y Vite para el frontend. Necesitas **Git**, **Docker Desktop**
(con contenedores Linux) y **Node.js con npm**. El proyecto de Supabase debe
tener aplicadas las migraciones de `database/supabase/migrations/`.

### 1. Clonar y configurar

En PowerShell, clona el repositorio una vez que la versión con `compose.yaml`
esté publicada en la rama que usarás:

```powershell
git clone https://github.com/AntonioJCB/TC3008AVJW.git
cd TC3008AVJW
Copy-Item backend/.env.example backend/.env
Copy-Item frontend/.env.example frontend/.env
```

Si ya tienes el repositorio, empieza en los comandos `Copy-Item`. Si ya tienes
los archivos `.env`, consérvalos y no vuelvas a copiarlos encima. Completa las
variables siguientes con valores
**del mismo proyecto de Supabase**:

| Archivo | Variables necesarias | Dónde obtenerlas |
| --- | --- | --- |
| `backend/.env` | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | URL del proyecto y llave **legacy service_role** en Supabase Dashboard. Esta llave solo va en el backend. |
| `frontend/.env` | `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY` | URL del mismo proyecto y llave publicable en Supabase Dashboard. |
| `frontend/.env` | `VITE_API_URL=http://localhost:8000` | Dirección local del backend en Docker. |

`SHODAN_API_KEY` es opcional. Su plan debe permitir las consultas DNS y host
para que esa fuente funcione. Docker instala theHarvester y SpiderFoot durante
la construcción: no necesitas clonarlos ni instalarlos en tu computadora. Los
archivos `.env` contienen credenciales y están excluidos de Git.

Si usas la base compartida del equipo, **no vuelvas a aplicar las migraciones**.
Para preparar una base nueva o revisar una existente, sigue la guía de
[base de datos](docs/database/README.md) antes de iniciar análisis.

### 2. Iniciar backend y fuentes OSINT

Abre Docker Desktop y, desde la raíz del repositorio, ejecuta:

```powershell
docker compose config --quiet
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
```

`backend` y `spiderfoot` deben aparecer como `healthy`, y `/health` debe
responder `disponible`. La primera construcción necesita Internet y puede
tardar varios minutos.
La documentación de la API queda en <http://127.0.0.1:8000/docs>.

### 3. Iniciar el frontend

En **otra terminal** de PowerShell:

```powershell
cd frontend
npm ci
npm run dev
```

Abre la dirección que muestre Vite, normalmente <http://localhost:5173>.
Inicia sesión con una cuenta vinculada a una organización para entrar al
portal cliente. Los análisis requieren una autorización vigente para el dominio.
Mantén Docker Desktop activo mientras uses la aplicación.

### 4. Volver a iniciar o detener

Después de la primera instalación, desde la raíz del repositorio basta con
`docker compose up -d` para iniciar el backend y SpiderFoot. Para ver errores,
usa `docker compose logs --tail=100 backend spiderfoot`. Detén Vite con
`Ctrl+C` en su terminal y los contenedores con `docker compose down`. Ese
comando conserva el volumen de datos de SpiderFoot.

Para instalación manual del backend consulta [backend/README.md](backend/README.md);
para comprobaciones de las fuentes y problemas de conexión consulta la
[guía de Docker y OSINT](docs/backend/docker-osint.md).

## Equipo

- Antonio Jesús Calderón Burgos
- Jaime Gámez Gómez-Rubalcava
- Valeria Pérez Mendoza
- Willian Salomon Lemus Sanchez

## Aviso de uso

Este proyecto está diseñado exclusivamente para fines académicos y defensivos. Los análisis deben realizarse únicamente sobre dominios propios, ficticios o expresamente autorizados.
