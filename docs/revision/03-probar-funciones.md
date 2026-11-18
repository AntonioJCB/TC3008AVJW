# Probar BaxterSec y distinguir un cero válido de una falla

Revisión del 18 de noviembre de 2026. Las secciones de lectura no cambian la base.
Las secciones marcadas **con escritura** son un procedimiento futuro para un
entorno de desarrollo autorizado; no se ejecutaron durante esta revisión.
Consulta [funcionamiento y resultados observados](01-funcionamiento-y-diagnostico.md)
y [arranque](02-ejecutar-proyecto.md).

## 1. Qué prueba cada nivel

| Nivel | Evidencia | Lo que no demuestra |
|---|---|---|
| Lint/tipos | Código frontend coherente estáticamente | Login o red real |
| Tests Python | Reglas/adaptadores/control con entradas conocidas | Acceso a proveedores o Supabase real |
| Salud HTTP | Procesos y conectividad interna | Escrituras, RLS o riesgo correcto |
| Lectura Supabase | Tablas y resultados disponibles | Permisos efectivos de un usuario de navegador |
| Consulta OSINT nueva | Respuesta del proveedor al objetivo | Persistencia, salvo ejecutar el flujo integrado |
| Escaneo integrado | UUID, crudos, observaciones y puntaje guardados | Ausencia de vulnerabilidades |

## 2. Tests existentes, sin consultas OSINT reales

Desde un entorno Python que tenga las dependencias de `backend/pyproject.toml`
instaladas, entra a `backend`:

```bash
python -m pytest -q -p no:cacheprovider
```

En la revisión el entorno local antiguo no tiene `pydantic_settings` ni
`sqlalchemy`, por lo que cinco módulos fallan durante recolección. Esto no es
un fallo de score y no se arregló instalando paquetes. Cuando se autorice preparar
ese entorno, la instalación prevista en el proyecto es `python -m pip install -e ".[dev]"`.

Los módulos que pudieron ejecutarse en ese entorno dieron 85 pruebas exitosas:

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_risk_engine.py tests/test_collectors.py tests/test_settings.py tests/test_osint_normalization.py tests/test_ingestion.py tests/test_scan_service.py
```

| Archivo de tests | Responsabilidad |
|---|---|
| `test_risk_engine.py` | Puertos, CVE, CT, correos, pesos, confianza, cobertura y parcialidad |
| `test_collectors.py` | Respuestas HTTP simuladas, formatos y errores de herramientas |
| `test_settings.py` | Variables, placeholders y credenciales incompatibles |
| `test_osint_normalization.py` | Normalización, alcance y descarte de eventos |
| `test_ingestion.py` | Crudos, deduplicación y llamadas a ingesta |
| `test_scan_service.py` | Estados, fallos aislados, cancelación y persistencia coordinada |
| `test_supabase_contract.py` | Constructor real de consultas con transporte simulado |
| `test_orchestrators.py` | Orquestación y endpoints con dependencias sustituidas |
| `test_authorization.py` | Aislamiento de organización, rol y vigencia de autorización |
| `test_admin_invites.py` | Invitaciones y permisos de plataforma simulados |
| `test_health.py` | Salud y conexión PostgreSQL opcional simulada |

La imagen productiva no incluye necesariamente pytest ni la carpeta `tests`:
no des por válido `docker compose exec backend pytest` sin comprobar su contenido.

Frontend, desde `frontend/`:

```bash
npm run lint
npx tsc --noEmit --incremental false -p tsconfig.app.json
npx tsc --noEmit --incremental false -p tsconfig.node.json
```

Estos tres chequeos pasaron durante la revisión. Un `tsc -b --dry` no sustituye
al chequeo de tipos: solo anuncia qué proyectos construiría.

## 3. Salud y autenticación, solo lectura

```bash
docker compose ps
curl -i http://127.0.0.1:8000/health
curl -i http://127.0.0.1:8000/api/escaneos
curl -i -H 'Authorization: Bearer 1' http://127.0.0.1:8000/api/escaneos
```

Esperado: contenedores saludables, salud 200 y rutas protegidas 401 en ambas
solicitudes sin token válido. Se verificó este resultado. Si la ruta opcional
`/api/v1/health/db` devuelve 503, revisa su configuración PostgreSQL directa antes
de inferir una desconexión de la Data API de Supabase.

En Swagger usa solo el access token de una sesión de usuario. No uses el UUID,
`1`, llave publicable ni `service_role` como sesión del portal.

## 4. Trazar un escaneo existente, solo lectura

1. Abre el frontend con una cuenta del cliente.
2. En Network, revisa peticiones a `puntajes_riesgo`, `escaneos`, `observaciones`
   y `resultados_fuentes`. Guarda ID del escaneo y respuesta numérica, no tokens.
3. En Supabase Table Editor usa filtros con ese mismo UUID:

| Tabla | Filtro | Revisar |
|---|---|---|
| `escaneos` | id = UUID | Estado, organización y fechas |
| `resultados_fuentes` | escaneo_id = UUID | Una fila por fuente prevista, errores y contadores |
| `resultados_crudos` | escaneo_id = UUID | Contenido original, hash, estado de ingesta |
| `observaciones` | escaneo_id = UUID | Atributos y activo relacionado |
| `hallazgos` | escaneo_id = UUID | Regla, evidencia, peso/aporte históricos |
| `puntajes_riesgo` | escaneo_id = UUID | Global, categorías, versión, cobertura y parcialidad |

4. Compara la base con Network y con la tarjeta del último análisis terminado.
5. Abre el historial y limpia Desde/Hasta en la gráfica. Un punto es un escaneo
   finalizado con puntaje, no un activo ni un hallazgo individual.
6. Si la base tiene un score positivo para un análisis del mismo cliente y
   Network lo devuelve, pero la gráfica lo convierte en 0, conserva captura y
   respuesta como evidencia de presentación. Si Network devuelve 0 y la base
   también, investiga hacia atrás en reglas y observaciones.

No uses la visualización de datos desde el SQL Editor como prueba de RLS del
navegador: ese acceso puede tener privilegios distintos.

## 5. Simular el motor sin escribir ni consultar proveedores

Desde `backend/`, este ejemplo usa IP documental y objetos sintéticos. No hace
peticiones de red. Comprueba cero por inventario y resultado positivo por SSH:

```bash
.venv/bin/python - <<'PY'
from app.risk.modelos import Obs, Regla
from app.risk.motor import evaluar_riesgo

reglas = [Regla('r1', 'INFRA-001', 'Administración remota', 'infraestructura', 'alta', 15)]
inventario = Obs('o1', 'a1', 'dominio', 'ejemplo.test', 'descubierto', {}, 'SpiderFoot', 'f1')
ssh = Obs('o2', 'a2', 'servicio', '203.0.113.10:22/tcp', 'servicio_expuesto', {}, 'SpiderFoot', 'f1')
for nombre, observaciones in [('Solo inventario', [inventario]), ('Servicio SSH', [ssh])]:
    r = evaluar_riesgo(observaciones, reglas, {'SpiderFoot': 'completado'})
    print(nombre, r.puntaje.puntaje_global, [h.regla_codigo for h in r.hallazgos])
PY
```

Con el motor 1.1.0 local: inventario 0; SSH 13 e `INFRA-001`.
Esto demuestra que el algoritmo puede producir positivos cuando recibe las
condiciones exigidas. No demuestra que el objetivo real tenga SSH expuesto.
No insertes fixtures en una organización real para forzar que la gráfica suba.

Para evaluar observaciones reales sin guardar, usa `cargar_observaciones`,
`cargar_reglas`, `cargar_estado_fuentes` y `evaluar_riesgo`; no llames a
`calcular_y_guardar`, que sí hace la RPC de escritura. Antes compara la versión
del motor con `puntajes_riesgo.version_motor`. Tres simulaciones reales durante
la revisión devolvieron 0, coincidiendo numéricamente con sus filas guardadas;
no equivalen a validar toda la lógica del motor remoto 1.3.2.

## 6. Verificar herramientas sin lanzar un análisis

```bash
docker compose exec backend /opt/theHarvester/.venv/bin/theHarvester -h
docker compose exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://spiderfoot:5001/', timeout=10).status)"
```

Para comparar módulos y fuentes sin exponer llaves:

```bash
docker compose exec backend python -c "from app.settings import get_settings; s=get_settings(); print('SpiderFoot:', s.spiderfoot_modules); print('theHarvester:', s.theharvester_sources)"
```

Revisar un resultado crudo ya persistido en la pantalla Fuentes permite ver qué
devolvió realmente cada herramienta. Cero observaciones puede deberse a una
lista vacía, formato no soportado, información fuera de alcance o descarte por
el adaptador. No es equivalente a «la herramienta encontró cero vulnerabilidades».

Shodan: comprobar `/api-info` valida la llave; comprobar `/dns/resolve` valida
permiso de ese endpoint; `/shodan/host/{ip}` tiene su propio resultado. Si falta
Membership en DNS, no hay motivo para cambiar Supabase. No se revalidó la cuenta
Shodan mediante una petición externa nueva en esta revisión.

## 7. Escaneo integrado nuevo — con escritura, pendiente de autorización

Este recorrido crea datos en Supabase y un escaneo en SpiderFoot. Ejecutarlo solo
cuando se autorice, con un dominio propio o con permiso verificable y entorno de
desarrollo. Antes debe resolverse cuál versión del backend se va a usar.

1. Confirma organización, dominio y autorización vigente; no analices dominios
   de terceros elegidos solo para buscar un score positivo.
2. Abre Network y activa conservar peticiones.
3. Pulsa Nuevo análisis una vez; `POST /api/escaneos` debe devolver 201 y UUID.
4. `POST /api/escaneos/{id}/ejecutar` debe devolver 202.
5. Observa `GET /api/escaneos/{id}` durante la ejecución; el portal consulta
   aproximadamente cada cinco segundos.
6. Comprueba resultados por fuente, crudos, observaciones y puntaje por el mismo UUID.
7. Compara número de fuentes previstas con ejecutadas y faltantes; el código local
   espera cuatro, pero el catálogo remoto contiene cinco.
8. Si hay cuatro éxitos locales: completado. Si hay algún éxito y fallos: incompleto.
   Si ninguna termina: fallido. Cancelación es un estado aparte.
9. El riesgo se calcula después del cierre del escaneo, por lo que puede aparecer
   unos instantes más tarde. Un error de cálculo no borra los crudos guardados.
10. Recarga el navegador y vuelve al historial. El UUID debe persistir.

En Vercel/hosting compartido, resolver DNS no demuestra que la IP completa sea
propiedad del cliente ni autoriza evaluar todos sus servicios. Revisa el alcance
antes de cualquier nueva fuente o comprobación activa.

## 8. Recálculo, cancelación y permisos — con escritura

No se ejecutaron durante la revisión. En desarrollo, cuando se autorice:

- Recálculo: conservar captura/valores previos, POST a `/riesgo/recalcular`,
  comprobar un puntaje por escaneo y estado analítico de hallazgos conservado.
  No debe aparecer un nuevo escaneo OSINT. No recalcular con una versión antigua
  sobre datos de 1.3.2 sin evaluar compatibilidad.
- Cancelación: iniciar un análisis de prueba, detenerlo como solicitante o admin
  de organización, comprobar `cancelado`, fuentes pendientes detenidas y crudos
  previamente completados conservados. No hay reanudación garantizada.
- Aislamiento: con otra cuenta/organización, GET de un UUID ajeno debe negarse
  según el contrato; no basta con probar usando service_role. Un lector no debe
  crear análisis; un admin de organización no se convierte por ello en admin
  de plataforma.
- Administración: invitación, asignación y edición de reglas son operaciones
  reales. Probar con cuentas destinadas a desarrollo, no con correos arbitrarios.

## 9. Matriz para interpretar fallos

| Síntoma | Próxima comprobación |
|---|---|
| 401 | Sesión/access token y proyecto de Auth |
| 403 al crear | Perfil, rol, organización activa y autorización |
| 404 de ruta en Supabase | URL REST frente a URL base y endpoint solicitado |
| 502/503 backend | Logs, configuración, disponibilidad y RPC/tablas requeridas |
| 403 Shodan | Plan/permisos de la cuenta, no instalación de Docker |
| Fuente completada pero vacía | Crudo, conteos y alcance; no asumir evidencia |
| Muchas observaciones, score 0 | Tipos/atributos, pesos, reglas activas y versión |
| Hallazgos históricos pero score 0 | El score local es por escaneo, no suma todo el inventario |
| Base positiva pero gráfico vacío | Cliente, UUID, límite 50, fecha de fin y filtros |
| Cálculo diferente al histórico | Versión del motor, calibración vigente, fechas y datos originales |
| Incompleto con es_parcial=false | Inconsistencia de datos/versiones a investigar |

Registra evidencia por UUID y versión antes de proponer una corrección. El
objetivo de las pruebas es trazabilidad, no obligar a que todos los análisis
produzcan un score mayor a cero.
