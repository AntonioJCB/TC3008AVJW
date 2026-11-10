# Backend

## Estado actual

FastAPI expone las rutas de escaneo en `backend/app/main.py`. Supabase Auth valida
el token; la API consulta el perfil activo y la organización antes de acceder a
un escaneo. El dominio objetivo se obtiene de `organizaciones.dominio_principal`
y se compara con una autorización vigente. El cliente no envía un dominio libre
para ejecutar el análisis.

El flujo es: crear escaneo pendiente, iniciarlo, consultar cuatro fuentes OSINT,
guardar respuestas crudas, normalizar y deduplicar observaciones, calcular
hallazgos y puntajes, y exponer el estado por API. Los fallos de una fuente no
cancelan las demás; el estado final puede ser `completado`, `incompleto` o
`fallido`.

## Interpretación del Risk Score

El motor calcula un puntaje **por escaneo** con las observaciones de ese
escaneo. Una fuente puede terminar correctamente y aportar dominios o IPs sin
activar ninguna regla de riesgo; entonces el puntaje puede ser 0. El inventario
de activos y los hallazgos históricos de la organización no se suman al
puntaje de un escaneo nuevo. Si alguna fuente falla, `es_parcial` indica que
el 0 puede subestimar la exposición.

El catálogo contiene 16 reglas. La calibración `20261110000000` deja activas
solo las seis con evaluador (`INFRA-001/002/003`, `CONF-001/002` e `IDEN-003`).
Las diez pendientes siguen visibles en el catálogo, pero inactivas.
Descubrir una IP o un dominio, por sí solo, no demuestra una vulnerabilidad y
no incrementa el score. Los certificados vistos solo en Certificate
Transparency y los correos públicos producen hallazgos informativos con peso
0 hasta contar con evidencia verificable. Una CVE que la fuente haya marcado
explícitamente como no verificada se descarta. El motor guarda la versión
`1.1.0`; los puntajes históricos no se recalculan automáticamente.
Las CVE sin un servicio concreto asociado se conservan como observaciones,
pero tampoco aportan puntaje.

## Mapa del código

- `app/main.py`: rutas HTTP, autenticación y comprobación del alcance.
- `app/settings.py`: configuración de Supabase y de los collectors desde `.env`.
- `app/scan_service.py`: ciclo de vida del escaneo y persistencia por fuente.
- `app/orchestrators.py`: ejecución aislada de crt.sh, Shodan, theHarvester y SpiderFoot.
- `app/osint_normalization.py` y `app/ingestion.py`: normalización y guardado de observaciones.
- `app/risk/`: reglas, cálculo y persistencia del riesgo.
- `app/api/routes/health.py`: rutas de salud heredadas; la comprobación de PostgreSQL directo usa `app/core/config.py`.

## Contrato HTTP

| Método | Ruta | Función |
| --- | --- | --- |
| GET | `/health`, `/api/v1/health` | Salud del proceso. |
| GET | `/api/v1/health/db` | Conexión PostgreSQL directa opcional. |
| POST | `/api/admin/clientes/{id}/usuarios/invitar` | Invitar por Auth y asignar al cliente; requiere administrador de plataforma activo. |
| POST | `/api/escaneos` | Crear escaneo con `autorizacion_id`. |
| GET | `/api/escaneos` | Historial de la organización. |
| POST | `/api/escaneos/{id}/ejecutar` | Reclamar e iniciar el trabajo; responde 202. |
| POST | `/api/escaneos/{id}/detener` | Detener el análisis propio; un admin de la organización puede detener cualquiera. |
| GET | `/api/escaneos/{id}` y `/fuentes` | Estado general y por fuente. |
| GET | `/api/escaneos/{id}/hallazgos` y `/riesgo` | Resultados guardados. |
| POST | `/api/escaneos/{id}/riesgo/recalcular` | Recalcular sin consultar las fuentes. |

Las rutas de escaneo requieren `Authorization: Bearer <access_token>` de
Supabase. El contrato generado está disponible en `/docs` cuando la API corre.

## Límites actuales

- El trabajo en segundo plano vive en el proceso FastAPI. Al reiniciar, se
  cierran escaneos antiguos, pero no hay una cola persistente ni reanudación.
- La cancelación conserva los resultados ya completados y marca como detenidas
  las fuentes pendientes. Requiere la migración `20261105000000_cancelar_escaneo.sql`.
  En la instalación actual de un solo proceso, detiene theHarvester y solicita
  la detención del escaneo remoto de SpiderFoot. Para varios workers o réplicas
  se necesita mover el control de trabajos a una cola compartida.
- `service_role` se usa en el servidor para operaciones internas; hay que
  mantener la llave fuera del navegador y seguir revisando los permisos.
- El inicio transaccional usa la función SQL `iniciar_escaneo`. Si esa migración
  falta, existe una ruta de compatibilidad temporal con el inicio anterior.
- El portal cliente usa esta API para crear y ejecutar análisis; los resultados
  se leen desde Supabase.

Consulta [backend/README.md](../../backend/README.md) para instalación,
variables de entorno y pruebas. El trabajo pendiente está en
[siguientes-pasos.md](siguientes-pasos.md).
Para revisar las fuentes externas, consulta [osint.md](osint.md).
Para levantar el backend y las herramientas con Docker, sigue
[docker-osint.md](docker-osint.md).
