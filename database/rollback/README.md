# Rollback manual de `guardar_riesgo`

`20261112000000_sincronizar_hallazgos_riesgo.rollback.sql` restaura la
definición de `public.guardar_riesgo` de la migración
`20261017120000_motor_de_riesgo.sql`, incluidos sus permisos. Está fuera de
`supabase/migrations` para que `supabase db push` no lo ejecute por accidente.

El archivo solo cambia la función. **No es un respaldo de datos**: no elimina
marcas `evidencia.retirado_del_riesgo`, no restaura hallazgos que se hayan
borrado antes y no revierte puntajes calculados ni análisis posteriores. La
función antigua vuelve a borrar hallazgos `abierto` que no estén en un recálculo.

Si hubiera que revertir en producción:

1. Confirmar el proyecto objetivo y que no haya escaneos en ejecución.
2. Desplegar la versión del backend y frontend compatible con la función
   anterior. El código nuevo también puede leerla, pero deja de conservar
   estados `aceptado` o `revisado` al insertar hallazgos de otro escaneo.
3. Revisar y ejecutar el SQL del rollback en una transacción. Para que el
   historial de Supabase refleje la reversión, crear una **nueva migración**
   con la función y los permisos del archivo (sin sus líneas `BEGIN`/`COMMIT`)
   y aplicarla; no cambiar ni borrar la migración ya aplicada.
4. Comprobar la definición y el permiso:

   ```sql
   SELECT
     pg_get_functiondef('public.guardar_riesgo(uuid,jsonb,jsonb)'::regprocedure)
       LIKE '%DELETE FROM public.hallazgos%' AS version_anterior_activa,
     has_function_privilege(
       'service_role',
       'public.guardar_riesgo(uuid,jsonb,jsonb)'::regprocedure,
       'EXECUTE'
     ) AS service_role_puede_ejecutar;
   ```

Para recuperar datos anteriores a una ejecución de la función se necesita
un respaldo independiente; este archivo no puede reconstruirlos.
