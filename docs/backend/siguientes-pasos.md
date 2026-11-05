# Siguientes pasos para corregir el backend

Las reparaciones locales de `feature/portal-integration` recuperan los módulos
faltantes y alinean las migraciones. La suite de backend pasa y las migraciones
se probaron en PostgreSQL temporal. Falta validar la integración en un proyecto
Supabase de desarrollo antes de desplegar.

## 1. Validar contra Supabase de desarrollo

- Comparar el esquema actual y la tabla de historial de migraciones con los
  archivos de `database/supabase/migrations/`. Revisar datos existentes antes
  de agregar restricciones de unicidad.
- Aplicar las migraciones en orden y cargar `seed.sql` en ese entorno aislado.
- Probar con dos organizaciones: crear autorización, crear y ejecutar escaneo,
  consultar estados, resultados, hallazgos y riesgo, y negar acceso cruzado.
- Simular una fuente fallida, dos ejecuciones simultáneas y un recálculo.

**Criterio:** el flujo completo produce datos reales en la base de desarrollo,
no duplica activos o puntajes y no revela datos de otra organización.

## 2. Hacer durables los escaneos

Sustituir `BackgroundTasks` por un trabajo persistido y un worker. Definir
reclamo atómico, heartbeat, reintentos, tiempo límite y recuperación tras
reinicio. Mantener los endpoints y formatos de respuesta actuales.

**Criterio:** reiniciar la API durante un escaneo no pierde el trabajo ni lo
ejecuta dos veces; el usuario puede consultar su estado final.

## 3. Endurecer permisos y autorización

Separar las lecturas del usuario de las escrituras internas con `service_role`.
Probar RLS y permisos de cada rol con una base de desarrollo. Definir el proceso
para comprobar y conservar la evidencia de autorización del dominio; hoy la
organización puede registrar su propia autorización.

**Criterio:** ninguna ruta o función privilegiada permite saltar de organización,
escalar rol o analizar un dominio sin autorización vigente y verificable.

## 4. Reducir acoplamiento y preparar despliegue

Dividir `app/main.py` en routers, esquemas y servicios manteniendo el contrato
HTTP. Unificar la configuración de Supabase y PostgreSQL opcional; documentar
qué dependencias se usan en cada flujo. Actualizar el SDK de Supabase en un
cambio separado con pruebas de contrato. Añadir pruebas de instalación limpia
y un procedimiento de despliegue y reversión de migraciones.

**Criterio:** cada cambio pasa la suite, la API arranca desde un entorno limpio
y una versión nueva puede desplegarse detrás de una base migrada sin interrumpir
los escaneos existentes.

## 5. Conectar el frontend

Implementar sesión real de Supabase en el frontend y consumir la API con el
access token. Reemplazar los datos simulados pantalla por pantalla, empezando
por historial y estado de escaneo. Mantener los mocks solo para desarrollo.

**Criterio:** el usuario inicia sesión, ejecuta un escaneo autorizado y ve sus
resultados persistidos sin datos de demostración mezclados.
