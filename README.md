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

## Tecnologías previstas

- **Frontend:** React, Vite y TypeScript.
- **Backend:** Python y FastAPI.
- **Base de datos:** PostgreSQL.
- **Entorno de desarrollo:** Docker y Docker Compose.
- **Despliegue del frontend:** Vercel.

## Estructura inicial

```text
TC3008AVJW/
├── backend/     # API, orquestación y procesamiento
├── frontend/    # Dashboard web
└── database/    # Migraciones y recursos de PostgreSQL
```

## Flujo de ramas

- main: versión estable y conectada a producción.
- dev: integración y pruebas antes de producción.
- feature/\*: desarrollo de nuevas funcionalidades.
- fix/_: corrección de errores.
  Los cambios deben enviarse mediante Pull Request:
  feature/_ → dev → main
  Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para conocer las reglas de colaboración.
  Estado del proyecto
  Actualmente se está preparando la estructura inicial del monorepo.
  Ejecución local
  Las instrucciones de instalación y ejecución se agregarán cuando estén configurados el frontend, el backend y Docker.

## Equipo

- Antonio Jesús Calderón Burgos
- Jaime Gámez Gómez-Rubalcava
- Valeria Pérez Mendoza
- Willian Salomon Lemus Sanchez

## Aviso de uso

Este proyecto está diseñado exclusivamente para fines académicos y defensivos. Los análisis deben realizarse únicamente sobre dominios propios, ficticios o expresamente autorizados.

## Backend OSINT

El backend Python ejecuta crt.sh, Shodan, theHarvester y SpiderFoot en paralelo. Un error de proveedor no detiene los demás; el escaneo termina como `incompleto` si falla alguna fuente. Cada reporte se guarda con hash en `resultados_crudos`, se normaliza y deduplica, y sus activos/hechos se registran en `activos` y `observaciones`. `resultados_fuentes` conserva el estado, error y conteos de cada proveedor. Esta etapa no compara los hechos con `reglas_riesgo` ni crea hallazgos.

Requisitos locales:

- Python 3.11 o superior para la API.
- theHarvester instalado como ejecutable disponible en `PATH` (o configura `THEHARVESTER_BIN`). Instala la versión de theHarvester compatible con su propio requisito de Python.
- SpiderFoot ejecutándose localmente en `http://127.0.0.1:5001`.
- Una API key de Shodan.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Completa `backend/.env` con la URL de Supabase, la clave secreta de servidor y la API key de Shodan. La clave `SUPABASE_SERVICE_ROLE_KEY` nunca debe ir en el frontend ni en el repositorio. Aplica las migraciones de `database/supabase/migrations/` después del esquema base y antes de iniciar escaneos.

El campo `autorizaciones_dominio.alcance` debe incluir el dominio raíz de forma explícita (por ejemplo, `empresa.com`). Para aceptar tanto el raíz como sus subdominios, registra `empresa.com, *.empresa.com`; un comodín por sí solo no habilita el dominio raíz.

El frontend crea primero una fila pendiente en `escaneos` usando la sesión autenticada. Después llama `POST /api/escaneos/{id}/ejecutar` a esta API y envía el JWT de Supabase como `Authorization: Bearer <access_token>`. La respuesta incluye estado y error por proveedor; `GET /api/escaneos/{id}/fuentes` permite consultar el mismo detalle más tarde.

### Prueba offline

Desde `backend/`, ejecuta la empresa sintética `Empresa Demo Ficticia`:

```bash
python -m app.demo
python -m app.demo --json
python -m unittest discover -s tests -v
```

El demo usa el dominio reservado `empresa-demo.test` y direcciones/documentos de ejemplo. No llama a Internet, no inicia herramientas externas y no escribe en Supabase. Los tests de `test_ingestion.py` usan un cliente simulado para comprobar lotes y reintentos; para comprobar escritura real, aplica las migraciones, configura `backend/.env` y ejecuta el endpoint con un escaneo autorizado.

### Fuentes TypeScript

Los archivos de `backend/src/osint/` ya no son importados por FastAPI; la implementación activa está en `backend/app/`. Se conservan por ahora como referencia para comparar la migración y no afectan el runtime Python. Cuando el equipo confirme que Python es la única implementación y no necesita esa referencia, se pueden retirar en un cambio separado.
