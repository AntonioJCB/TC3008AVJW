# Frontend

## Estado actual

La aplicación principal está en `frontend/` y usa React, Vite y TypeScript.
`/login` inicia sesión con Supabase Auth. `AuthProvider` comprueba la sesión
con Auth y carga `public.usuarios` usando la llave publicable y el token del
usuario. `/home` exige un perfil activo con organización. `/admin` exige una
membresía activa en `public.administradores_plataforma`; el rol `admin` de
`public.usuarios` solo administra su propia organización. Al iniciar sesión,
un administrador de plataforma entra directamente a `/admin`. El cierre de
sesión elimina la sesión local.

La ruta `/admin` lista clientes y permite crearlos. Cada fila ofrece un menú
de tres puntos para abrir la ficha de empresa (`/admin/clientes/:id`) o
eliminarla. Los clientes con datos se archivan para conservar el historial;
los vacíos se pueden borrar. En la ficha se edita el nombre, dominio, estado
y cuentas. «Agregar usuario» abre un formulario que invita por Supabase Auth
o asigna una cuenta existente sin cliente. La sección de configuración guarda
las reglas editadas con una sola acción transaccional; las fuentes OSINT siguen
siendo un catálogo de lectura porque sus colectores se configuran en backend.

`/home` conserva los estilos y la composición de `feature/base-frontend` y usa
`ClientPortalPage` y `clientData.ts`: consulta la organización del
perfil autenticado, escaneos, activos, autorizaciones, hallazgos, puntajes,
resultados por fuente, observaciones y explicaciones. Las consultas quedan
filtradas por `organizacion_id` y protegidas por RLS. El resumen usa el último
análisis terminado; las secciones muestran estados vacíos si el cliente no
tiene datos. Los hallazgos incluyen todos los análisis del cliente; el
detalle de fuentes y observaciones usa el último análisis terminado. La
pantalla «Fuentes» conserva el inventario, filtros y paneles laterales del
frontend base; muestra estados, duración y métricas de normalización guardadas
para ese análisis. El botón «Actualizar fuentes» vuelve a consultar Supabase.
La cobertura se calcula como proporción de colectores completados y la
contribución como proporción de observaciones generadas; no se usan los
porcentajes ilustrativos de la maqueta. La lectura de activos se limita a los
100 más recientes, hallazgos a 100 y el
historial a 50; se muestran los conteos totales.

«Nuevo análisis» crea y ejecuta un escaneo autorizado mediante FastAPI. Durante
la ejecución, el panel superior muestra avance por fuentes, duración de cada
consulta y observaciones guardadas, actualizados cada cinco segundos. Un admin
de la organización puede detener cualquier análisis; un analista, solo los que
inició. Las fuentes ya completadas se conservan. El botón necesita que el
backend anuncie soporte para la operación de cancelación.

Los componentes `*Mock.ts` y la antigua `DashboardPage.tsx` siguen en el
repositorio como prototipo, pero ya no están enrutados. El portal no ofrece un
asistente interactivo todavía. La app Vite en
`database/` es otra interfaz y no sustituye al frontend principal.

## Estructura

- `src/routes/AppRoutes.tsx` y `RequireAuth.tsx`: rutas y guardias de acceso.
- `src/controllers/AuthProvider.tsx`: sesión, perfil y operaciones de Auth.
- `src/pages/login/`: formulario de inicio de sesión.
- `src/pages/admin/AdminPortalPage.tsx` y `AdminClientPage.tsx`: panel interno y ficha de cliente.
- `src/pages/dashboard/ClientPortalPage.tsx` y `services/clientData.ts`:
  portal real del cliente y consultas a Supabase.
- `src/pages/dashboard/`: conserva el layout y los componentes del prototipo.
- `src/pages/dashboard/**/services/*Mock.ts` y `demoData.ts`: escenarios de
  muestra para la maqueta.

## Integración pendiente

1. Añadir paginación a las listas que superen los límites actuales.
2. Implementar el asistente interactivo.
3. Retirar los componentes de maqueta sin rutas cuando termine la integración.

Consulta [frontend/README.md](../../frontend/README.md) para instalar y ejecutar
la interfaz. El contrato disponible del backend está en
[Backend](../backend/README.md).
