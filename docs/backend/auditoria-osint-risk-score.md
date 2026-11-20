# Auditoría del análisis OSINT y Risk Score

Revisión del 12 de noviembre de 2026 en `fix/backend-corrections`.

## Flujo comprobado

`main.py` valida sesión, organización y autorización; `scan_service.py` inicia
el trabajo; `orchestrators.py` ejecuta las cuatro fuentes; `ingestion.py` y la
función SQL `ingestar_observaciones` guardan activos y observaciones con claves
únicas; `risk/persistencia.py` combina hallazgos actuales con los pendientes
del último snapshot persistente; `guardar_riesgo` escribe hallazgos y puntaje
en una transacción. El portal consulta las tablas de la organización en Supabase.

Un hallazgo pertenece a un activo y a un escaneo. El activo y el escaneo
pertenecen a la organización; el dominio principal es el punto de entrada del
análisis. `resuelve_a` conserva la relación observada entre nombre e IP. Una
IP de hosting compartido se registra, pero sus puertos y CVE no se atribuyen
como riesgo de la empresa sin autorización explícita para esa IP o CIDR.

## Causas encontradas y correcciones

| Causa | Corrección | Archivo |
| --- | --- | --- |
| El plan de objetivos se cerraba antes de consultar fuentes; los subdominios descubiertos entraban solo en el siguiente escaneo. | Ampliación acotada en la misma ejecución, con nuevas consultas a las fuentes pertinentes y persistencia inicial por fuente. | `app/orchestrators.py`, `app/scan_service.py`, `app/main.py` |
| Un proveedor interno de theHarvester podía fallar y descartar datos de otro que sí respondió. | Conserva la respuesta válida y registra la incidencia como resultado parcial. | `app/orchestrators.py` |
| Las CVE de IP quedaban normalizadas sin un evaluador que las puntuara. | Evalúa CVE de IP autorizada y elimina duplicados de la misma CVE ya asociada a un servicio de esa IP. | `app/risk/reglas.py`, `app/risk/persistencia.py` |
| Un corte transitorio de Supabase dejaba un escaneo finalizado sin puntaje. | Reintento del cálculo y recuperación al consultar el estado del escaneo. | `app/scan_service.py`, `app/main.py` |
| La función SQL solo retiraba hallazgos obsoletos en estado `abierto`. | Migración que marca los obsoletos fuera del riesgo sin borrar la fila ni el estado decidido por el analista; backend y portal los excluyen de vistas vigentes. | `database/supabase/migrations/20261112000000_sincronizar_hallazgos_riesgo.sql`, `app/risk/persistencia.py`, `frontend/src/pages/dashboard/services/clientData.ts` |
| El portal limitaba la lectura a 100 activos y 100 hallazgos. | Lectura paginada de activos, hallazgos y observaciones de los activos visibles. | `frontend/src/pages/dashboard/services/clientData.ts` |

## Resultados y límites

La suite del backend pasó con 140 pruebas, incluidos escenarios de subdominio
descubierto que produce un hallazgo, fallo de una fuente con puntaje parcial,
IP autorizada, CVE duplicada, arrastre de hallazgo no resuelto y resolución.
El frontend pasó TypeScript, ESLint y compilación.
El contenedor local del backend se reconstruyó y reinició el 12 de noviembre;
Docker lo reportó como saludable y `GET /health` respondió `disponible`.
Al revisar de nuevo el 16 de noviembre, los contenedores no estaban levantados.

En el último escaneo real consultado (`af531bcb-9f0b-40c3-9df6-1f2999ce2412`),
SpiderFoot guardó 18 observaciones y theHarvester 4; Shodan falló y crt.sh no
aportó observaciones. No hubo hallazgos verificables; el puntaje guardado fue
`0`, marcado como parcial. Este escaneo se ejecutó antes de desplegar las
correcciones de ampliación y no valida por sí solo el nuevo flujo.
El último escaneo consultado el 16 de noviembre (`02ce17ee-3119-4c83-a563-7c39e0f640a0`)
también tiene 0 hallazgos y puntaje 0 parcial. No se ha demostrado con un
escaneo real nuevo que las fuentes actuales produzcan un hallazgo puntuable.

El puntaje 60 de los escaneos de octubre procede de datos de demostración,
incluidos `203.0.113.10` y un emisor `Demo CA`. La línea base persistente no
importa esos hallazgos. Los hallazgos reales posteriores a la línea base se
arrastran mientras sigan activos; un hallazgo resuelto sale del puntaje y
puede reaparecer si un escaneo futuro vuelve a confirmarlo.

Las fuentes actuales de SpiderFoot se centran en DNS. Shodan requiere un plan
que permita las consultas configuradas. Descubrir un activo no confirma una
vulnerabilidad; los certificados históricos de CT y correos públicos tienen
peso cero según la calibración vigente. El límite `SCAN_MAX_TARGETS` es 20 por
defecto. El análisis se mantiene en técnicas OSINT pasivas.

La migración `20261112000000_sincronizar_hallazgos_riesgo.sql` se aplicó
manualmente en el proyecto `hqxqryamgfqpougitqwm`. El 16 de noviembre se
verificó la función remota, el permiso de `service_role` y se registró la
versión en el historial. `supabase db push --dry-run --include-all --remote`
terminó sin migraciones pendientes. En PostgreSQL 16 temporal se comprobó que
no borra filas, preserva `aceptado` y `resuelto`, no toca otro escaneo, es
idempotente y reactiva un hallazgo si vuelve a aparecer en el resultado.

## Diagnóstico del análisis del 16 de noviembre

El escaneo `00cc1acf-8334-4f0e-b566-a36b3f83245f` terminó incompleto.
SpiderFoot generó 16 observaciones: nombres, IPs y resoluciones DNS de
dominio y subdominios. Su resultado crudo no contiene eventos de puerto
expuesto ni CVE. Las seis reglas activas no consideran esas observaciones un
riesgo; por eso el puntaje 0 de este escaneo es coherente con la evidencia.
Shodan rechazó las consultas por el plan de la cuenta. crt.sh devolvió un
arreglo vacío; se reprodujo la consulta pasiva del dominio exacto y la de
subdominios con el mismo resultado. No hay evidencia de un fallo del
normalizador de certificados en este caso.

theHarvester sí se ejecutó y produjo IPs. Tres observaciones quedaron
persistidas, pero su resultado crudo acabó en estado `error` y la fuente se
marcó fallida. Esto localiza el problema después de la ejecución de la
herramienta. Se añadió un reintento idempotente a la RPC de ingesta para el
caso de respuesta perdida tras confirmar datos. La causa exacta de la
excepción histórica no puede recuperarse porque el contenedor que produjo
ese escaneo ya fue recreado. El siguiente escaneo real debe confirmar si el
reintento resuelve ese síntoma.

Se corrigió además la ruta de CVE asociadas a `dominio` y `subdominio`: el
normalizador las guardaba, pero el evaluador solo aceptaba `ip` y `servicio`.
La atribución del hallazgo persistente ahora comprueba el alcance de esos
nombres. crt.sh consulta cada nombre autorizado del inventario y los nuevos
subdominios descubiertos; si una búsqueda por comodín no devuelve registros,
consulta el nombre exacto.

La suite completa pasó con 144 pruebas y dos subtests. Incluye un flujo con
dos subdominios, una fuente fallida, CVE en ambos nombres y puntaje parcial,
además de deduplicación y persistencia. El backend local fue reconstruido y
`GET /health` respondió `disponible`. Aún no se ha ejecutado un nuevo escaneo
real después de estas correcciones; la salud del contenedor no demuestra que
los proveedores externos vayan a devolver hallazgos puntuables.

## Ampliación de postura web del 16 de noviembre

Se agregó una quinta fuente, `Web`, para comprobar cada hostname autorizado con
una única petición `HEAD /` a HTTP y HTTPS. La conexión usa una IP pública
resuelta, SNI y encabezado `Host` del nombre autorizado; no sigue redirecciones
ni recorre enlaces. La fuente registra la vigencia del certificado TLS actual,
un error de validación del certificado o HTTP sin redirección a HTTPS. DNS,
IPs descubiertas y certificados históricos siguen siendo informativos.

La migración `20261116000000_postura_web_autorizada.sql` se aplicó al proyecto
enlazado y registró la fuente y tres reglas. El dry-run posterior quedó al
día. Desde el contenedor local, el dominio principal devolvió certificado
verificado y `www.receta-gastro-centro-app.vercel.app` devolvió error de
validación TLS por nombre (`verify_code=62`). El flujo aislado de colector,
normalizador y motor produjo un hallazgo y 12 puntos parciales para `www`.
`api` y `dev` agotaron el tiempo de HTTPS en la prueba desde Windows; esos
timeouts no se puntúan como vulnerabilidades.

La suite actual pasó con 148 pruebas y dos subtests. El contenedor local del
backend está saludable. Este resultado todavía no está guardado como nuevo
escaneo en Supabase: un análisis real posterior debe confirmar la ingesta, el
puntaje persistido y su visualización en el portal.

## Corrección del flujo pasivo del 17 de noviembre de 2026

`Web` era un comprobador interno activo: abría conexiones TCP/TLS y enviaba
`HEAD /` a los hosts. Se retiró del plan de ejecución, de la cobertura y del
cálculo de riesgo. Se conservan código y filas históricas. Las reglas
CONF-001/002/006/007/008 quedaron inactivas; el catálogo remoto se actualizó
sin cambiar pesos y existe una migración versionada para reproducir el cambio.
La actualización remota se hizo sobre los datos del catálogo; la migración
`20261117163000_retirar_web_osint_pasivo.sql` aún no está registrada como
aplicada en el historial remoto.

El inventario mezclaba observaciones de todos los análisis para la columna
Fuentes, aunque el último análisis de crt.sh devolviera cero. Dos análisis de
octubre incluían datos de demostración (`203.0.113.10`, `Demo CA`), por lo que
sus nombres siguen existiendo como procedencia histórica. La vista ahora
separa fuentes con observaciones en el último análisis de fuentes históricas.
La exposición usa hallazgos puntuables, vigentes y asociados al activo; los
informativos se muestran aparte. Un activo descubierto sin evaluación de
seguridad sigue `Sin evaluar`; una evaluación negativa explícita o un hallazgo
resuelto permite `Evaluado sin hallazgos`. La resolución DNS observada genera
aristas entre nombres e IPs; ya no se dibuja una relación directa con toda IP
por el mero hecho de estar en el inventario.

En el escaneo anterior `78d23833-030e-4cf4-ad88-c18fff58f72e`, el hallazgo
CONF-006 de Web quedó conservado con `retirado_del_riesgo=true` y el puntaje
recalculado pasó de 12 a 0. Su estado de ejecución histórico sigue
`incompleto`, porque refleja los timeouts que ocurrieron entonces.

El nuevo escaneo real `ccf90e3a-de9e-48cd-9139-7a9f019c1797` del dominio
autorizado `receta-gastro-centro-app.vercel.app` finalizó `completado`.
Ejecutó únicamente crt.sh, theHarvester y SpiderFoot. crt.sh consultó con
éxito y obtuvo cero registros; theHarvester completó sus proveedores sin
resultados; SpiderFoot produjo 18 observaciones de nombres, IPs y resoluciones
DNS, con cero activos nuevos. Los tres resultados crudos quedaron procesados.
Cuatro reglas activas fueron evaluadas (IDEN-003 e INFRA-001/002/003), sin
hallazgos confirmados. Se guardó Risk Score 0, no parcial. Ninguna IP
descubierta se añadió como objetivo de consulta y no se alteró la integración
de SpiderFoot.

La suite del backend pasó con 165 pruebas y dos subtests; TypeScript, ESLint y
la compilación del frontend pasaron. El backend local se reconstruyó y Docker
lo reportó saludable. La inspección visual del portal llegó a la pantalla de
acceso; el usuario estaba interactuando con esa ventana, por lo que no se
completó una verificación visual autenticada del inventario.
