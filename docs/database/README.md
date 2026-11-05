# Base de datos

## Modelo actual

Supabase usa PostgreSQL y Auth. `auth.users` contiene las identidades;
`public.usuarios` guarda perfil, rol y organización. Las tablas principales
son `organizaciones`, `autorizaciones_dominio`, `escaneos`, `fuentes_osint`,
`resultados_fuentes`, `resultados_crudos`, `activos`, `observaciones`,
`hallazgos`, `reglas_riesgo`, `puntajes_riesgo`, `explicaciones_ia` y
`bitacora_auditoria`.

`public.administradores_plataforma` guarda la membresía interna de BaxterSec,
separada de `usuarios.rol`. Una persona puede conservar su rol dentro de un
cliente y administrar la plataforma al mismo tiempo. La membresía no se puede
crear desde el frontend.

```text
organización → autorización → escaneo
                         escaneo → estado por fuente → resultado crudo
                         escaneo → observaciones → activos
                         escaneo → hallazgos → puntaje de riesgo
```

Las políticas RLS separan las filas por organización. El backend usa la llave
`service_role` únicamente en el servidor para tareas internas; esa llave evita
RLS y exige comprobar organización y permisos en cada operación del backend.

## Migraciones

`database/supabase/migrations/` es la fuente para construir una base nueva.
Se aplica en orden de nombre:

1. `20261016000000_esquema_base.sql`: tablas e índices base.
2. `20261016033436_integrar_auth_y_rls.sql`: perfiles de Auth, funciones y RLS.
3. `20261016204803_registrar_estado_fuentes.sql`: estado de cada collector.
4. `20261016211140_agregar_ingesta_observaciones_osint.sql`: observaciones, deduplicación y función de ingesta.
5. `20261017120000_motor_de_riesgo.sql`: restricciones y escritura atómica del riesgo.
6. `20261017130000_iniciar_escaneo_atomico.sql`: reclamo e inicio transaccional.
7. `20261017140000_proteger_creacion_organizacion.sql`: impide altas desde perfiles inactivos.
8. `20261104000000_administracion_plataforma.sql`: membresía de plataforma, lectura de clientes y alta auditada.
9. `20261104001000_asignar_usuarios_clientes.sql`: lista perfiles sin cliente y permite asignarlos con rol validado y auditoría.
10. `20261104002000_gestion_clientes_y_reglas.sql`: actualización, estado y eliminación segura de clientes, cuentas y reglas.
11. `20261104003000_configurar_reglas_riesgo_lote.sql`: guarda los cambios de reglas en una sola transacción.
12. `20261105000000_cancelar_escaneo.sql`: estado `cancelado` y cierre atómico de las fuentes pendientes al detener un análisis.

Después de aplicar las migraciones en un proyecto nuevo, identifica el UUID
del usuario interno en **Authentication → Users** y asígnale la membresía desde
el SQL Editor con una cuenta que administre la base:

```sql
INSERT INTO public.administradores_plataforma (usuario_id)
VALUES ('UUID_DEL_USUARIO_INTERNO');
```

No asignes esta membresía en un trigger de registro ni a todos los usuarios con
`rol = 'admin'`: ese rol solo administra un cliente. En el proyecto enlazado
actual se vinculó a la única cuenta admin activa sin cambiar su rol de cliente.
`listar_clientes()` devuelve clientes y conteos de integrantes, y
`crear_cliente(nombre, dominio)` registra un cliente y escribe en la bitácora.
Ambas funciones comprueban la membresía y que el perfil esté activo.
`listar_usuarios_sin_cliente()` y `asignar_usuario_cliente()` permiten vincular
una cuenta ya creada en Supabase Auth a un cliente. La asignación solo admite
perfiles activos sin organización; no traslada cuentas entre clientes.
`configurar_reglas_riesgo_lote()` valida todas las reglas antes de actualizar
ninguna y registra los cambios en la bitácora. Si una regla es inválida, la
operación completa se revierte.

`database/baxtersec_schema.sql` es el esquema base original; no se aplica
además de la primera migración. `database/supabase/seed.sql` carga las cuatro
fuentes OSINT y las reglas iniciales. Los pesos son datos de catálogo y pueden
ajustarse sin editar el motor de riesgo.

La carpeta `database/` también contiene una pequeña app Vite que consulta
`organizaciones` con una llave publicable. No forma parte de las migraciones ni
del dashboard principal.

## Aplicación segura a una base existente

1. Identificar qué migraciones ya registra Supabase y comparar las tablas,
   columnas, funciones, índices y restricciones actuales. La migración base es
   idempotente respecto a nombres de tablas e índices, pero no reconcilia un
   esquema distinto que ya use esos nombres.
2. Comprobar si hay activos, resultados crudos, hallazgos o puntajes duplicados;
   las migraciones posteriores añaden restricciones de unicidad.
3. Aplicar primero en un proyecto de desarrollo aislado y probar Auth, RLS,
   creación de escaneos, ingesta y recálculo.
4. Planear respaldo y ventana de despliegue antes de aplicar al proyecto real.
   Desplegar el código backend después de la base migrada.

La validación local de esta rama aplicó las migraciones anteriores y el seed en
PostgreSQL temporal con un esquema mínimo simulado de Supabase Auth. Las
migraciones de plataforma y asignación se aplicaron al proyecto Supabase
enlazado. Allí se verificó que un perfil `lector` solo ve su organización y
que el alta de clientes y la asignación requieren membresía de plataforma.
