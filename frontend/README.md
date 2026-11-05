# Frontend de BaxterSec

Prototipo navegable con React, Vite y TypeScript. El acceso conserva la composición de `feature/login` y siempre usa **Negative Zone**. El panel reproduce la estructura del dashboard de la propuesta visual y permite cambiar a **Azul pizarra**.

## Inicio local

Desde `frontend/`:

```powershell
npm install
Copy-Item .env.example .env
npm run dev
```

Configura `VITE_SUPABASE_URL` y `VITE_SUPABASE_PUBLISHABLE_KEY` en `.env` con
los valores del mismo proyecto Supabase que usa el backend. La llave publicable
puede vivir en el navegador; nunca coloques `service_role` ni `sb_secret_` aquí.
Configura `VITE_API_URL` con la dirección de FastAPI para invitar usuarios desde
la ficha de cada cliente (en local, `http://localhost:8000`). La API necesita
estar encendida para esta acción. Agrega la URL de `/restablecer-clave` a las
redirecciones permitidas en **Supabase Auth → URL Configuration**; usa la misma
dirección base que `FRONTEND_URL` del backend.

Para comprobar el proyecto:

```powershell
npx tsc -b
npm run lint
npm run build
```

## Recorrido de demostración

- `/login`: inicia sesión con Supabase Auth y consulta el perfil en `public.usuarios`.
- `/admin`: panel interno de BaxterSec para administradores de plataforma; lista clientes, permite crearlos y guarda cambios de reglas desde un único botón cuando hay ediciones.
- `/admin/clientes/:id`: ficha de empresa para editar datos, cambiar estado y gestionar cuentas. El botón «Agregar usuario» abre un formulario para invitar una cuenta nueva o asignar una cuenta existente sin cliente.
- `/home`: requiere una sesión válida y un perfil activo asociado a una organización. Muestra nombre, dominio, puntaje, activos y hallazgos reales del cliente.

- `/home/activos`: activos registrados del cliente.
- `/home/relaciones`: observaciones del último análisis terminado.
- `/home/fuentes`: estado real de las fuentes del último análisis terminado.
- `/home/hallazgos`: hallazgos registrados de los análisis del cliente.
- `/home/historial`: escaneos y puntajes guardados.
- `/home/asistente`: explicaciones guardadas; el chat interactivo aún no está conectado.
- `/home/configuracion`: datos de cuenta, autorizaciones y tema visual.

El portal de cliente reutiliza los estilos y la composición de
`feature/base-frontend`. Sus tarjetas y listados reciben datos de Supabase;
las pantallas de demostración originales permanecen en el repositorio como
referencia, pero no están conectadas a `/home`.

El portal de cliente y la vista de administración consultan Supabase con RLS.
«Nuevo análisis» usa FastAPI; el panel de progreso muestra duración y resultados
por fuente y permite detener un análisis en curso según el rol. Los archivos
`*Mock.ts` y la antigua `DashboardPage.tsx` permanecen como referencia visual,
pero no están en las rutas activas.

## Registro de estilos

- `src/styles.css`: colores de los temas y estilos compartidos.
- `src/pages/dashboard/dashboard.css`: estructura general del panel y transición breve entre pantallas.
- `src/pages/dashboard/components/header/header.css`: cabecera del panel y sus estados de demostración.
- `src/pages/dashboard/components/sidebar/sidebar.css`: sidebar del mockup, incluidos sus ajustes para portátil y móvil.
- `src/pages/dashboard/screens/overview/overview.css`: tarjetas, gráfica, tabla y secciones del Resumen.
- `src/pages/dashboard/screens/assets/assets.css`: cabecera, indicadores, inventario, panel lateral, ficha y adaptación móvil de Activos.
- `src/pages/dashboard/screens/relations/relations.css`: indicadores, grafo, nodos, paneles y adaptación móvil de Relaciones.
- Cada pantalla puede mantener sus estilos propios junto a sus componentes.

## Organización

```text
src/
  components/                 Componentes compartidos, como la marca
  controllers/                Estado del tema, sesión y perfil de Supabase
  routes/                     Rutas de la aplicación
  services/                   Persistencia local de la preferencia visual
  pages/
    login/
      components/             Panel de presentación y formulario visual
      controller/             Inicio de sesión y redirección según rol
    admin/                     Vista protegida de administración
      LoginPage.tsx
      login.css
    dashboard/
      components/             Diálogo y piezas compartidas
        header/               Cabecera del panel y sus estilos
        sidebar/              Componente y estilos de la barra lateral
      services/               Escenario ficticio compartido
      screens/
        overview/
          components/         Tarjetas y gráfica del resumen
          services/           Series y cifras ilustrativas
        assets/
          components/         Indicadores, tabla, panel lateral y ficha
          controller/         Búsqueda, filtros, paginación y selección
          services/           Inventario estático de la maqueta
          AssetsScreen.tsx
          assets.css
        relations/
          components/         Indicadores, grafo, detalle y rutas
          controller/         Selección y restablecimiento del foco
          services/           Nodos, conexiones y rutas simuladas
          RelationsScreen.tsx
          relations.css
        sources/              Fuentes previstas
        findings/             Hallazgos y filtro de severidad
        history/              Estado vacío de historial
        assistant/            Respuestas preparadas
        settings/             Selección de tema
      DashboardPage.tsx
      dashboard.css
```

Cada vista del panel está aislada en su carpeta. Los componentes del resumen y del login viven junto a su pantalla; los elementos que comparten varias vistas permanecen en `dashboard/components`.
