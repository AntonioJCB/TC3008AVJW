# Backend

## Estado actual

FastAPI expone las rutas de escaneo en `backend/app/main.py`. Supabase Auth valida
el token; la API consulta el perfil activo y la organización antes de acceder a
un escaneo. El dominio objetivo se obtiene de `organizaciones.dominio_principal`
y se compara con una autorización vigente. El cliente no envía un dominio libre
para ejecutar el análisis.

El flujo es: crear escaneo pendiente, iniciarlo, consultar tres fuentes pasivas activas,
guardar respuestas crudas, normalizar y deduplicar observaciones, calcular
hallazgos y puntajes, y exponer el estado por API. Los fallos de una fuente no
cancelan las demás; el estado final puede ser `completado`, `incompleto` o
`fallido`.

Al iniciar, la API toma el dominio principal y los dominios/subdominios e IPs del
inventario de esa organización que estén bajo el dominio principal autorizado.
La autorización del dominio principal cubre sus subdominios registrados en el
inventario; un alcance `*.ejemplo.com` por sí solo no permite iniciar el
análisis del dominio raíz. El
límite `SCAN_MAX_TARGETS` (20 por defecto) evita trabajos sin cota. crt.sh y
theHarvester consultan los nombres; SpiderFoot consulta nombres e IPs
autorizadas. Web queda fuera del flujo OSINT pasivo porque abría conexiones
HTTP y TLS directamente a los hosts. Las IPs pueden
autorizarse por dirección o CIDR en `alcance`. Un servicio se consulta mediante
su IP, sin sondear directamente el puerto. Si un proveedor falla solo en
algunos objetivos, se conservan sus resultados válidos y el escaneo queda
incompleto. Una IP de hosting compartido descubierta por DNS no demuestra
propiedad y no entra como objetivo sin autorización explícita.
Los subdominios nuevos descubiertos durante el análisis se pasan también a las
fuentes restantes en la misma ejecución, hasta `SCAN_MAX_TARGETS` y el tiempo
límite del escaneo. Se conserva la ingesta inicial si se detiene la ampliación.
Las IPs descubiertas se registran, pero solo se consultan como objetivos cuando
el alcance autoriza explícitamente la IP o su CIDR. theHarvester conserva los
datos de proveedores que sí respondieron aunque otro proveedor interno falle.

La vista Relaciones agrupa los activos del inventario alrededor del dominio
principal y muestra primero sus subdominios. Las líneas entre un nombre y una
IP requieren una observación `resuelve_a` del último análisis; la pertenencia
de un subdominio o correo al dominio no demuestra exposición de seguridad.

## Interpretación del Risk Score

Desde el motor `1.3.2`, cada análisis calcula sus hallazgos con la evidencia
actual y conserva los hallazgos abiertos del último análisis persistente de la
misma organización. El mismo activo y regla se cuentan una sola vez. Si una
fuente no vuelve a reportar una señal, el hallazgo continúa en el puntaje con
`evidencia.pendiente_revalidacion=true` y la referencia del último análisis
que sí la confirmó. Mientras haya hallazgos pendientes de revalidación, el
puntaje se marca como parcial. Un analista o administrador puede marcarlo como resuelto
en la pantalla de Hallazgos; el puntaje del último análisis baja y el hallazgo
ya no se arrastra. Si un análisis posterior lo detecta otra vez, reaparece.

El primer análisis con esta versión inicia una línea base nueva: los puntajes
anteriores no se importan como riesgos vigentes, porque el historial contiene
escaneos de demostración. Los resultados anteriores permanecen en el historial.
Una fuente puede terminar correctamente y aportar dominios o IPs sin activar
ninguna regla de riesgo; entonces el puntaje puede ser 0. Si alguna fuente
falla, `es_parcial` indica que el resultado puede subestimar la exposición.
El backend reintenta el cálculo si se interrumpe la conexión con Supabase.
Si el escaneo ya terminó sin puntaje, la siguiente consulta de su estado
intenta recuperarlo sin volver a ejecutar las fuentes. Un fallo permanente
del motor queda registrado en los logs para su diagnóstico.

El catálogo contiene 19 reglas. En el flujo pasivo quedan activas
`INFRA-001/002/003` e `IDEN-003`. `CONF-001/002` requerían corroboración TLS
activa y `CONF-006/007/008` provenían de Web; ahora están inactivas. Sus pesos
y filas se conservan para interpretar el historial. El puntaje aplica confianza
y combinación decreciente, no una suma simple.
Descubrir una IP o un dominio, por sí solo, no demuestra una vulnerabilidad y
no incrementa el score. Los certificados vistos solo en Certificate
Transparency y los correos públicos producen hallazgos informativos con peso
0 hasta contar con evidencia verificable. Una CVE que la fuente haya marcado
explícitamente como no verificada se descarta. Los puntajes históricos no se
recalculan automáticamente.
Los servicios y CVE de una IP solo aportan puntos si la autorización incluye
esa IP o una red CIDR que la contenga. Las observaciones de IPs compartidas
siguen visibles para investigar relaciones, pero no se atribuyen como riesgo
de infraestructura de la empresa.
Las CVE asociadas directamente a una IP autorizada también pueden aportar
puntaje; las CVE de IPs compartidas quedan excluidas. Al aplicarse, la migración
`20261112000000_sincronizar_hallazgos_riesgo.sql` marca con
`evidencia.retirado_del_riesgo=true` los hallazgos que ya no cumplen una regla.
Conserva la fila y su estado para auditoría; el backend y el portal los omiten
del riesgo vigente. El estado `aceptado` o `revisado` también pasa al siguiente
escaneo cuando el hallazgo sigue activo. Ya está aplicada al proyecto remoto.
SpiderFoot usa un perfil pasivo acotado. Google Public DNS DoH aporta postura
DNS estructurada y urlscan aporta banners web históricos para nombres exactos.
Los proveedores de IP quedan deshabilitados hasta declarar
la modalidad de uso de InternetDB. Consulta `spiderfoot-pasivo-20261118.md` para conocer la atribución, las
limitaciones y qué señales pueden llegar a las reglas existentes.

## Mapa del código

- `app/main.py`: rutas HTTP, autenticación y comprobación del alcance.
- `app/settings.py`: configuración de Supabase y de los collectors desde `.env`.
- `app/scan_service.py`: ciclo de vida del escaneo y persistencia por fuente.
- `app/orchestrators.py`: ejecución de crt.sh, theHarvester y SpiderFoot; Web opcional con consentimiento.
- `app/web_posture.py`: comprobaciones HTTP y TLS activas del FQDN autorizado en 80/443.
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
| POST | `/api/escaneos/{id}/hallazgos/{hallazgo_id}/resolver` | Resolver un hallazgo del último análisis y actualizar su Risk Score; requiere analista o admin de la organización. |
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
