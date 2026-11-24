# Censys Platform sustituye a Shodan

El flujo nuevo ejecuta **crt.sh, Censys, theHarvester y SpiderFoot**. Shodan deja
de consultarse. Se conservan sus filas de catálogo, adaptador y compatibilidad
de reglas para interpretar escaneos anteriores sin cambiar su procedencia.

## Reglas inactivas y significado de completado

`completado` indica que todas las fuentes previstas terminaron correctamente;
`incompleto`, que alguna falló y otra respondió; `fallido`, que ninguna completó.
Esto se calcula en `scan_service.compute_scan_state`, independientemente de
cuántas reglas estén activas o cuántos hallazgos haya.

Las reglas sin evaluador o evidencia disponible se mantienen inactivas; por
ejemplo, SPF/DMARC, filtraciones y secretos en repositorios necesitan fuentes o
comprobaciones adicionales. La calibración también da peso 0 a señales
informativas de correos públicos y certificados históricos de CT. El peso no
es lo mismo que `esta_activa`: una regla activa de peso 0 puede generar un
hallazgo informativo sin subir el score. No se activaron reglas ni se cambiaron
pesos en este cambio.

El catálogo remoto puede diferir de las migraciones locales y contiene datos de
otras versiones del motor. Revisa `reglas_riesgo` y la cobertura del escaneo;
no actives todo solo para obtener un score positivo. Cambiar Shodan por Censys
tampoco garantiza hallazgos ni un valor mayor que cero.

## Qué necesitas

1. Cuenta en [Censys Platform](https://platform.censys.io/).
2. En el menú de usuario, **API Access → Create New Token**, crea un Personal
   Access Token. Guarda su valor únicamente en el backend.
3. Permiso para **Get a host** y créditos/cuota disponibles. La documentación
   actual permite lookup de hosts a usuarios Free; no se usa búsqueda avanzada.
4. Opcional: ID de organización de **Censys** para usar sus permisos/créditos.
   Free no requiere ese ID. No es el UUID de organización en Supabase.
5. Para atribuir puertos/CVE a un cliente: una relación explícita entre su
   dominio y las IPs propias o autorizadas. DNS por sí solo no prueba propiedad.

No necesitas el antiguo API ID/API Secret de Legacy Search ni instalar un SDK:
el conector usa HTTPX y la API Platform v3.

Fuentes oficiales verificadas para la implementación:
[autenticación y acceso](https://docs.censys.com/reference/get-started),
[lookup de host](https://docs.censys.com/reference/v3-globaldata-asset-host),
[modelo Platform](https://docs.censys.com/docs/dataset-differences-legacy-search-censys-platform).
Las cuotas y campos disponibles dependen de tu cuenta; no se promete que Free
incluya todas las CVE/enriquecimientos ni búsquedas ilimitadas.

## Configuración en backend/.env

Agrega estas variables a tu archivo real, conservando Supabase y las otras fuentes:

```dotenv
CENSYS_PAT=TU_PERSONAL_ACCESS_TOKEN
CENSYS_ORGANIZATION_ID=
CENSYS_MAX_IPS=10
CENSYS_PAUSE_SECONDS=1.1
CENSYS_AUTHORIZED_IPS=
```

Las variables `SHODAN_*` ya no se usan. Puedes quitarlas de tu archivo local.
No pegues PATs en el chat, documentación, Git ni variables `VITE_*`.

Si tu infraestructura tiene IP propia/autorizada, declara el alcance por dominio:

```dotenv
# Ejemplo de formato: sustituye dominio e IP; la IP de documentación no es real.
CENSYS_AUTHORIZED_IPS='{"mi-dominio.com":["203.0.113.10"],"otro-dominio.com":["2001:db8::10"]}'
```

Usa el dominio canónico exacto, en minúsculas, sin esquema, ruta ni comodín. Cada
dominio tiene su propia lista: una IP autorizada para otro dominio no habilita
atribución al dominio actual. La IP debe además aparecer en la resolución DNS
del objetivo; no se consultan IPs arbitrarias de esa lista.

**Para tu aplicación en Vercel**, deja la lista vacía si solo eres dueño de la
aplicación y no de la IP compartida. El conector guarda crudos e inventario DNS,
pero descarta servicios de esas IPs con `servicios_sin_ip_autorizada`. Esto evita
atribuir SSH/bases de datos de un proveedor a tu aplicación. No llena el score
con vulnerabilidades ajenas. No se inicia un escaneo activo contra el host.

El límite de IPs evita consumo accidental de créditos. Si el DNS devuelve más
IPs que `CENSYS_MAX_IPS`, la fuente falla con un mensaje explícito antes de
consultar la API; no corta resultados silenciosamente como cobertura completa.

## Catálogo de Supabase

La migración nueva es
[`20261120210741_agregar_fuente_censys.sql`](../../database/supabase/migrations/20261120210741_agregar_fuente_censys.sql).
Solo hace un upsert de `Censys` en `fuentes_osint`. No renombra ni elimina Shodan,
no cambia reglas, ni recalcula los escaneos existentes. `seed.sql` registra
Censys en instalaciones nuevas; no ejecutes todo el seed sobre una base
calibrada solo para registrar esta fuente.

**Estado del equipo, 20 de noviembre de 2026:** se aplicó el registro de catálogo
en el Supabase configurado en el backend, mediante un upsert de datos equivalente
a este archivo. Se verificó una única fila `Censys/api_key` y el ID histórico de
Shodan conservado. No se modificaron reglas, observaciones ni puntajes.

La operación de datos no registra esta migración en el historial del CLI.
En otros entornos revisa y aplica únicamente este cambio mediante el procedimiento
del equipo. El upsert es idempotente, pero el historial de migraciones debe
gestionarse con el procedimiento habitual antes del despliegue.
No ejecutes un push de todas las migraciones pendientes sin comparar el esquema
remoto, que contiene resultados de versiones más nuevas que este checkout.

En Table Editor comprueba una fila `nombre=Censys`, `tipo_acceso=api_key`.
Si falta, el backend informa que falta Censys en el catálogo y no inicia el escaneo.

## Cómo probar sin escribir datos

Después de configurar el PAT, reconstruye la imagen para incluir el código nuevo
y recrea el backend para cargar variables. Antes confirma que este checkout es
la versión que deseas desplegar: el motor local actualizado se identifica como
1.1.1; no sustituye la lógica de versiones 1.3.x que aparecen en datos históricos.

```bash
docker compose build backend
docker compose up -d --no-deps --force-recreate backend
docker compose exec backend python -m app.check_censys --domain TU-DOMINIO.com
```

Este comando usa DNS y Censys reales, consume la cuota correspondiente y normaliza
en memoria. Imprime estado, cantidad de hosts, IPs autorizadas y observaciones;
**no crea escaneos ni guarda nada en Supabase**. La configuración general del
backend debe ser válida porque usa `get_settings()`.

Si solo cambiaste el PAT, omite el build: guarda `backend/.env` y usa
`docker compose up -d --no-deps --force-recreate backend`. Comprueba sin imprimir
el token:

```bash
docker compose exec backend python -c "from app.settings import get_settings; print('PAT configurado:', bool(get_settings().censys_pat))"
```

Si devuelve False, revisa que el archivo guardado contenga un token real en
`CENSYS_PAT`, no un placeholder `replace-...`. Compose no lee ediciones sin guardar.

| Resultado | Interpretación |
|---|---|
| Falta CENSYS_PAT | Agregar el token y recrear el contenedor |
| HTTP 401 | PAT incorrecto, revocado o expirado |
| HTTP 402 | Revisar créditos de la cuenta |
| HTTP 403 | Revisar permisos, organización elegida y acceso al lookup |
| HTTP 429 | Cuota/concurrencia: esperar y revisar el límite |
| HTTP 404 por host | No hay registro: se conserva como ausencia de datos, no error de integración |
| Error de formato/truncado | Respuesta incompleta o distinta del esquema; no se marca sana |
| Cero hosts | Censys no devolvió información para esas IPs |
| IPs autorizadas = 0 | Solo inventario DNS; no se atribuyen servicios compartidos |

El PAT va en `Authorization: Bearer ...`, nunca en la URL. Los mensajes de error
no incluyen cuerpos arbitrarios de la API ni la llave. No hay reintentos
automáticos sobre errores de cuenta/cuota para evitar gasto repetido.

## Cómo funciona el conector

1. Resuelve el dominio por DNS del sistema; conserva solo IPs públicas.
2. Valida límite y alcance de IPs por dominio.
3. Para cada IP hace GET a
   `https://api.platform.censys.io/v3/global/asset/host/{ip}` con PAT y, si se
   configuró, `organization_id` como query parameter.
4. Comprueba `result.resource.ip` y el formato de servicios; conserva la respuesta
   original en `hosts[]`, además de la correlación DNS propia.
5. La normalización produce relaciones DNS e IPs. Solo para las IPs
   expresamente autorizadas admite servicios TCP/UDP y sus CVE.
6. No convierte QUIC en TCP ni infiere CVE a partir de versiones de software.
   Las CVE deben venir en `services[].vulns[].id`; se guardan como reportadas,
   no como verificación técnica propia.
7. En un escaneo integrado, la ingesta guarda resultados crudos y observaciones;
   las reglas INFRA pueden usar Censys y SpiderFoot. Shodan solo permanece como
   compatibilidad para historial.

El portal conserva todo el catálogo para resolver nombres históricos, pero la
salud/cobertura usa las fuentes del análisis seleccionado. Antes del primer
análisis, muestra las cuatro fuentes actuales. Un análisis antiguo puede seguir
mostrando Shodan, como corresponde a su procedencia.

## Prueba integrada con escritura

Tras aplicar el registro de catálogo y configurar el PAT, inicia un análisis
autorizado desde el portal. Guarda el UUID y filtra por él en `escaneos`,
`resultados_fuentes`, `resultados_crudos`, `observaciones` y `puntajes_riesgo`.
Debe existir una fila para Censys, además de las otras tres fuentes. Si Censys
falla, el resto continúa y el resultado puede ser `incompleto`. Recargar el
portal debe recuperar los mismos datos.

La validación automatizada usa respuestas simuladas del formato oficial:

```bash
cd backend
python -m pytest -q tests/test_censys.py tests/test_risk_engine.py tests/test_scan_service.py
```

Sin una petición real no se puede certificar acceso, saldo ni datos de tu cuenta.
El contenedor confirmó PAT configurado el 20 de noviembre; no se hizo una petición
externa a Censys en esa comprobación. Sí se registró la fuente en Supabase, como
se describe arriba; no se modificaron credenciales ni escaneos remotos.
