# Backend de BaxterSec

API FastAPI para escaneos OSINT autorizados. Supabase Auth valida las sesiones;
PostgreSQL en Supabase guarda los escaneos, resultados crudos, observaciones,
activos, hallazgos, riesgo y bitácora.

## Flujo

1. El cliente envía un access token de Supabase y el ID de una autorización.
2. La API comprueba que el usuario esté activo, pertenezca a la organización y
   tenga rol `admin` o `analista` para crear o ejecutar un escaneo.
3. El dominio sale de `organizaciones.dominio_principal`, no del cuerpo HTTP.
   La autorización debe estar vigente e incluir ese dominio explícitamente.
4. `POST /api/escaneos/{id}/ejecutar` reclama el escaneo y prepara sus fuentes
   en una transacción mediante `iniciar_escaneo`. Mientras esa migración no esté
   aplicada, usa temporalmente el inicio anterior. La respuesta es `202`.
5. Los adaptadores consultan crt.sh, Shodan, theHarvester y SpiderFoot. Cada
   resultado se guarda, normaliza y deduplica por separado. Un fallo de una
   fuente no cancela las demás; el escaneo termina `completado`, `incompleto`
   o `fallido`.
6. El motor usa las observaciones y los pesos de `reglas_riesgo` para guardar
   hallazgos y puntajes. El recálculo usa las observaciones ya persistidas.

Los trabajos en segundo plano viven dentro del proceso FastAPI. Si este se
reinicia, el arranque cierra los escaneos que excedieron el tiempo límite.
Para trabajo distribuido o garantías de ejecución más fuertes hará falta una
cola persistente.

## Configuración local

Requiere Python 3.11 o posterior. Desde `backend/`:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload
```

Configura `SUPABASE_URL` y `SUPABASE_SERVICE_ROLE_KEY` en `backend/.env`.
La llave de servicio es solo para el servidor. `SHODAN_API_KEY` es opcional;
si falta, esa fuente se reporta fallida y el escaneo puede quedar incompleto.
Los demás binarios y tiempos se configuran con las variables documentadas en
`.env.example`. Define `CORS_ORIGINS` con los orígenes reales al desplegar y
`FRONTEND_URL` con la dirección pública del frontend para que las invitaciones
redirijan a `/restablecer-clave`.

theHarvester y SpiderFoot se instalan y arrancan por separado. En Windows,
`THEHARVESTER_BIN` debe apuntar a un ejecutable local de Windows; no sirve una
ruta `/Users/...` de macOS. SpiderFoot debe responder en `SPIDERFOOT_URL` antes
de iniciar un análisis. Una clave de Shodan puede ser válida y aun así devolver
403 si su plan no permite las rutas DNS y host. Consulta
[`docs/backend/osint.md`](../docs/backend/osint.md) para diagnóstico.
Para instalar las herramientas en contenedores de desarrollo, sigue
[`docs/backend/docker-osint.md`](../docs/backend/docker-osint.md).

`BAXTERSEC_DATABASE_URL` se usa únicamente para la ruta opcional
`GET /api/v1/health/db`, que prueba una conexión PostgreSQL directa. El flujo
de escaneos usa el cliente Supabase.

## Base de datos

Los archivos de `database/supabase/migrations/` se aplican en orden de nombre:
esquema base, Auth/RLS, estado por fuente, ingesta, riesgo, inicio atómico y protección de alta de organizaciones.
`database/supabase/seed.sql` carga fuentes y reglas iniciales de manera
idempotente. Una instalación anterior hecha con SQL manual debe comparar su
esquema e historial de migraciones antes de aplicar estas migraciones. No se
requiere copiar `database/baxtersec_schema.sql` por separado en una base nueva.

Aplica las migraciones nuevas antes de desplegar el backend. La ruta de inicio
conserva compatibilidad temporal si falta únicamente `iniciar_escaneo`, pero la
ingesta y el riesgo sí requieren sus tablas y funciones correspondientes.

## Rutas

- `GET /health`: proceso disponible.
- `GET /api/v1/health`: proceso disponible (ruta anterior conservada).
- `GET /api/v1/health/db`: conexión PostgreSQL opcional.
- `POST /api/admin/clientes/{id}/usuarios/invitar`: solo para administrador de
  plataforma activo; invita por Supabase Auth y asigna el perfil al cliente.
- `POST /api/escaneos`: crear escaneo pendiente.
- `GET /api/escaneos`: historial de la organización.
- `POST /api/escaneos/{id}/ejecutar`: iniciar escaneo.
- `POST /api/escaneos/{id}/detener`: cancelar un escaneo en curso.
- `GET /api/escaneos/{id}` y `/fuentes`: estado y avance.
- `GET /api/escaneos/{id}/hallazgos` y `/riesgo`: resultados.
- `POST /api/escaneos/{id}/riesgo/recalcular`: recalcular sin consultar fuentes.
- `GET /docs`: contrato OpenAPI.

Para las rutas de escaneo usa `Authorization: Bearer <access_token>`.

## Pruebas

Desde `backend/`, ejecuta `python -m pytest -q`. Las pruebas ordinarias usan
fuentes y respuestas simuladas; no escriben en Supabase. Las pruebas que escriben en una base real deben ejecutarse solo en un entorno de desarrollo aislado.
