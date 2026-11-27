# Traspaso para continuar BaxterSec OSINT

Actualizado el 17 de noviembre de 2026. Este documento resume lo comprobado hasta ese momento; antes de actuar, verifica el estado actual del repositorio, Docker y Supabase.

## Texto para iniciar la nueva conversación

> Continúa la integración del módulo OSINT de BaxterSec desde `docs/backend/traspaso-osint-nueva-conversacion.md`. Trabaja en el checkout `C:\Users\tonyc\Documents\Trabajos Tec\Ciberseguridad\TC3008AVJW`, rama `fix/backend-corrections`. Hay muchos cambios locales sin commit: revísalos y consérvalos. Primero valida un análisis **nuevo** con la versión actual de crt.sh y theHarvester, desde resultados crudos en Supabase hasta activos, Relaciones, observaciones, hallazgos y Risk Score. Comprueba la procedencia y los estados de cada proveedor de theHarvester, incluidos los resultados parciales. Shodan debe permanecer fuera de las fuentes activas; conserva su código y sus registros históricos. No modifiques SpiderFoot todavía. No inventes hallazgos cuando las fuentes devuelvan cero registros. Respeta el dominio autorizado y no hagas sondeos activos sobre IPs de alojamiento compartido sin autorización explícita. Si encuentras una falla, explica la causa, corrígela y prueba el flujo completo.

## Checkout y estado de trabajo

- Repositorio: `C:\Users\tonyc\Documents\Trabajos Tec\Ciberseguridad\TC3008AVJW`.
- Rama observada: `fix/backend-corrections`.
- Hay numerosos archivos modificados y archivos nuevos sin commit. **No descartarlos ni reemplazarlos en bloque.** Revisar `git status --short --branch` y diffs antes de editar.
- El checkout indicado en el contexto de Codex puede ser otro directorio; usar la ruta de arriba para esta tarea.
- `backend/.env` contiene configuración local y secretos; no copiarla al documento, al chat ni a Git. La variable local `THEHARVESTER_SOURCES` quedó en `certspotter,rapiddns,urlscan`.

## Comportamiento implementado

- Las fuentes activas del backend son `crt.sh`, `theHarvester`, `SpiderFoot` y `Web` (`backend/app/scan_service.py`). Shodan sigue implementado, pero no se ejecuta ni cuenta para el estado o cobertura de análisis nuevos.
- El portal excluye Shodan de las vistas de salud actuales. Conserva el catálogo para poder interpretar resultados históricos.
- crt.sh consulta el patrón `%.dominio` y el dominio exacto. Una consulta válida vacía no genera activos, observaciones ni hallazgos ficticios.
- theHarvester consulta por defecto CertSpotter, RapidDNS y urlscan. El adaptador conserva el JSONL con el estado de cada proveedor, su objetivo y la procedencia de cada resultado; mantiene resultados útiles cuando un proveedor falla. Guarda el JSONL incluso si ninguno completó.
- El normalizador acepta nombres, IPs, correos y hostnames derivados de URLs dentro del alcance. Los nombres repetidos entre objetivos se unifican y conservan sus proveedores. ASN y tipos sin activo compatible no se convierten en activos de riesgo.
- El análisis recorre el dominio principal y los subdominios registrados dentro del alcance autorizado, sujeto a `SCAN_MAX_TARGETS`. Las IPs compartidas no se convierten en objetivos de sondeo sin autorización explícita.
- SpiderFoot quedó sin cambios en esta fase.

## Evidencia real comprobada

El último análisis **finalizado y verificado** antes de este traspaso fue `6342c726-4500-4303-b0f0-df9143d81cf5`, iniciado el 17 de noviembre de 2026 a las 06:00 UTC. Se ejecutó **antes** de la última corrección de theHarvester.

- crt.sh: `completado`; las consultas para `%.receta-gastro-centro-app.vercel.app` y `receta-gastro-centro-app.vercel.app` dieron respuesta válida con **0 registros**. JSON crudo guardado como `procesado`. El reporte marcó como cubiertos el dominio principal y `api`, `dev`, `www`. Cero observaciones, activos nuevos, duplicados y hallazgos atribuibles a crt.sh. La ruta positiva con certificados y subdominios se probó con datos de prueba, pero aún no se observó en este dominio real.
- theHarvester anterior: cero observaciones. HackerTarget devolvió límite de cuota para los objetivos consultados. Su JSON anterior perdió el desglose de proveedores; esto motivó la corrección.
- Risk Score: **12**, parcial; el hallazgo abierto `CONF-006` proviene de Web. Las reglas `CONF-001`, `CONF-002` e `IDEN-003` tenían peso 0 en Supabase cuando se consultaron. Descubrimientos informativos no elevan el puntaje por sí solos.
- Una consulta directa al adaptador **nuevo** en el contenedor mostró RapidDNS y urlscan `completed/no-results`; CertSpotter `partial/invalid-response`; cero elementos. Esto demuestra ejecución y clasificación de proveedores, pero todavía no demuestra persistencia del nuevo formato en un análisis real de Supabase.
- Diagnósticos separados: HackerTarget `rate-limited/quota-exhausted`, OTX HTTP 429, Common Crawl `runtime-limit` a los 120 s. CertSpotter completó otra consulta sin resultados. Por esas limitaciones se eligió la lista predeterminada actual; una incidencia de CertSpotter debe seguir siendo visible como parcial.

## Validación realizada

- `backend/.venv/Scripts/python.exe -m pytest backend/tests -q`: **164 pruebas aprobadas**, 2 warnings de dependencias y 2 subtests aprobados.
- En `frontend/`: `npx tsc --noEmit`, `npm run lint` y `npm run build` terminaron correctamente.
- `git diff --check` sin errores.
- Se reconstruyó y recreó únicamente el servicio Docker `backend` con `docker compose up -d --build --no-deps backend`. Se verificó `healthy`, cuatro fuentes activas y `certspotter,rapiddns,urlscan` cargado. El contenedor SpiderFoot no se reconstruyó.

## Trabajo pendiente y criterio de cierre

1. Ejecutar un análisis nuevo desde la aplicación, con una autorización vigente. No reutilizar el análisis anterior como prueba del nuevo JSONL.
2. Consultar en Supabase `escaneos`, `resultados_fuentes`, `resultados_crudos`, `observaciones`, `activos`, `hallazgos` y `puntajes_riesgo` del nuevo `escaneo_id`. Verificar que el JSONL de theHarvester incluya `runs` e `items` y que el desglose del portal lo muestre.
3. Comprobar que cada nombre o IP devuelta por un proveedor se normalice dentro del alcance, se incorpore al inventario y aparezca en Relaciones cuando exista una relación sustentada. Si todos los proveedores devuelven cero registros, documentar esa limitación: no se puede demostrar descubrimiento real sin evidencia.
4. Confirmar que Shodan no tenga una fila de ejecución en el análisis nuevo y que no provoque `incompleto`. Las filas históricas pueden permanecer.
5. Confirmar que un proveedor parcial no borre los datos de otros y que el Risk Score use únicamente hallazgos vigentes puntuables. No subir pesos solo para obtener un número mayor.
6. Si crt.sh o theHarvester presentan una regresión, corregir esa fuente y repetir las pruebas de las otras. Revisar SpiderFoot **después** de cerrar esta validación.

## Archivos clave

- `backend/app/orchestrators.py`: selección de fuentes, objetivos, recolección y JSONL de theHarvester.
- `backend/app/osint_normalization.py`: transformación de registros en observaciones dentro del alcance.
- `backend/app/ingestion.py` y `backend/app/scan_service.py`: persistencia, estado y resultados crudos.
- `backend/app/risk/`: reglas, cálculo y persistencia del Risk Score.
- `frontend/src/pages/dashboard/screens/sources/LiveSourcesScreen.tsx` y `components/LiveSourceLogDialog.tsx`: inventario y desglose de fuentes.
- `frontend/src/pages/dashboard/ClientPortalPage.tsx`: salud de fuentes en Resumen.
- `backend/tests/test_collectors.py`, `test_osint_normalization.py`, `test_ingestion.py`, `test_orchestrators.py`, `test_scan_service.py`: pruebas de integración y regresión.
- `docs/backend/osint.md`: capacidades y limitaciones observadas de cada proveedor.

No se necesita una migración nueva para la corrección reciente de theHarvester o para desactivar Shodan. Según la conversación anterior, las migraciones de riesgo y Web se ejecutaron manualmente; confirmar sus versiones en la base antes de aplicar SQL adicional.

## Validación posterior: análisis del 17 de noviembre de 2026, 15:58 UTC

Se verificó en Supabase el análisis `78d23833-030e-4cf4-ad88-c18fff58f72e`, creado desde la aplicación a las 15:58:47 UTC y finalizado a las 16:00:03 UTC. La autorización `1b8e29dd-f6ad-470d-8cb7-283625abba89` seguía vigente y cubría `receta-gastro-centro-app.vercel.app`. La bitácora registró como objetivos solamente ese dominio y sus subdominios `api`, `dev` y `www`; ninguna IP compartida fue objetivo del análisis.

- `crt.sh`: `completado`, JSON crudo `procesado`. Las consultas exacta y `%.dominio` fueron válidas y devolvieron 0 registros. Cubrió los cuatro nombres; generó 0 observaciones, activos y hallazgos.
- `theHarvester`: `completado`, JSON crudo `procesado` con `runs` e `items`. Hay cuatro `runs` (uno por objetivo) y, en cada uno, CertSpotter, RapidDNS y urlscan figuran `completed/no-results` con `result_count: 0`. `items` y las listas heredadas están vacíos. No hay observaciones, activos nuevos ni hallazgos de esta fuente. La procedencia por proveedor se conserva en el formato; este análisis no aporta registros positivos para comprobar su incorporación real al inventario o a Relaciones.
- `SpiderFoot`: 18 observaciones y 0 activos nuevos; se consultó para verificar el flujo completo, sin cambiar su código.
- `Web`: `completado` con errores parciales por timeout HTTPS en `api` y `dev`, 2 observaciones. El hallazgo abierto `CONF-006` en `www` es atribuible a Web.
- `Shodan`: sin fila en `resultados_fuentes` para este análisis. Su entrada de catálogo y sus filas históricas permanecen.
- Risk Score: 12, `es_parcial: true`, `fuentes_faltantes: ["Web"]`. El aporte calculado de `CONF-006` es 11.52, redondeado a 12. No se elevó ningún peso ni se imputó riesgo a consultas sin resultados.

El diálogo de Fuentes contiene código para mostrar los `runs`, los estados y los resultados por proveedor, pero Opera no respondió al control de interfaz durante esta revisión; la visualización real del desglose queda sin comprobación directa. Las pruebas de los colectores, normalización, ingesta, orquestación y ciclo de escaneo pasaron (90/90); `npx tsc --noEmit` y `git diff --check` también pasaron. Las pruebas con datos de muestra verifican la conservación de resultados cuando un proveedor queda parcial o limitado, y la unificación de procedencias; no hubo un proveedor parcial en este análisis real.

Pendiente para demostrar descubrimiento real de crt.sh o theHarvester: repetir la trazabilidad de `items` → observaciones → activos → Relaciones cuando alguna fuente entregue un registro dentro del alcance. Cero registros no justifican fabricar evidencia ni hallazgos.
