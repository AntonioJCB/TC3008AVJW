# Backend de BaxterSec

Base ejecutable de la API en Python y FastAPI. Por ahora expone endpoints de
salud y prepara la configuración y el acceso a PostgreSQL. El flujo de análisis,
los endpoints de negocio, la normalización y la integración con el orquestador
se incorporarán en etapas posteriores.

## Estructura

```text
backend/
  app/
    api/             Routers HTTP versionados
    core/            Configuración de la aplicación
    db/              Motor y sesiones de PostgreSQL
    schemas/         Contratos HTTP (salud ahora; negocio después)
    services/        Lógica de aplicación independiente de HTTP
    main.py          Punto de entrada ASGI
  tests/             Pruebas propias del backend
  .env.example       Variables de entorno de ejemplo
  mock_data.json     Datos ficticios existentes para el PoC
  pyproject.toml     Dependencias y configuración de pruebas
```

La propuesta para las siguientes etapas es agregar `services/normalization/`
para convertir datos de fuentes externas en entidades canónicas,
`repositories/` para persistir resultados crudos y normalizados, y
`integrations/orchestrator/` como adaptador hacia el orquestador independiente.
La API recibirá y validará solicitudes del usuario; el orquestador ejecutará
la recolección y entregará resultados al backend mediante un contrato por
definir. No hay llamadas al orquestador en esta primera entrega.

## Inicio local

Requiere Python 3.11 o posterior. Desde `backend/`:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload
```

En Linux o macOS, activa el entorno con `source .venv/bin/activate` y copia
`.env.example` a `.env` con el comando de tu shell.

La aplicación carga `backend/.env` y permite sobrescribir sus valores con
variables de entorno. Cambia `BAXTERSEC_DATABASE_URL` por las credenciales de
tu PostgreSQL local. El servidor puede arrancar sin base de datos, pero el
chequeo de base devolverá 503 hasta que PostgreSQL esté configurado y accesible.
No se crean tablas automáticamente: el modelo y las migraciones se definirán
con los primeros casos de uso de datos.

## Comprobación

- `GET /api/v1/health`: confirma que el proceso responde.
- `GET /api/v1/health/db`: comprueba conexión a PostgreSQL con `SELECT 1`.
- `GET /docs`: documentación OpenAPI generada por FastAPI.

Desde `backend/`, ejecuta `python -m pytest` para las pruebas de la base.

## Decisiones pendientes para la siguiente etapa

- Contrato de solicitudes de análisis y validación del dominio autorizado.
- Formato de resultados crudos, activos normalizados y evidencias.
- Modelo relacional y migraciones de `scan_runs`, `raw_results`, `assets`,
  `findings` y `risk_scores`.
- Mecanismo de comunicación, autenticación y reintentos con el orquestador.

