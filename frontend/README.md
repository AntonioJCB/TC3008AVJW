# Frontend de BaxterSec

Prototipo navegable con React, Vite y TypeScript. El acceso conserva la composición de `feature/login` y siempre usa **Negative Zone**. El panel reproduce la estructura del dashboard de la propuesta visual y permite cambiar a **Azul pizarra**.

## Inicio local

Desde `frontend/`:

```powershell
npm install
npm run dev
```

Para comprobar el proyecto:

```powershell
npx tsc -b
npm run lint
npm run build
```

## Recorrido de demostración

- `/login`: entrada directa. Los campos son visuales y opcionales; el botón abre `/home` sin validar, enviar ni guardar credenciales.
- `/home`: resumen inspirado en la propuesta de diseño, con puntaje, desglose, gráfica interactiva, severidades, hallazgos, inventario, fuentes y recorrido de muestra.
- `/home/activos`: inventario normalizado de muestra, con búsqueda, filtros por tipo y novedades, paginación, selección de filas y ficha local del activo.
- `/home/relaciones`: grafo de exposición con selección de nodos, contexto y rutas prioritarias simuladas.
- `/home/fuentes`: colectores previstos, aún sin conexión.
- `/home/hallazgos`: hallazgos con filtro por severidad.
- `/home/historial`: estado vacío hasta que existan análisis reales.
- `/home/asistente`: respuestas ilustrativas predefinidas.
- `/home/configuracion`: selección de tema Negative Zone o Azul pizarra.

Las pantallas pendientes usan el escenario de `src/pages/dashboard/services/demoData.ts`, basado en `backend/mock_data.json`. Resumen, Activos y Relaciones usan datos estáticos propios en sus carpetas `services/` para reproducir la propuesta visual. En Activos hay 47 entidades simuladas, con siete filas por página; los contadores se calculan a partir de ellas y se actualizan al buscar o mostrar novedades. Relaciones muestra un subconjunto ilustrativo del grafo y permite explorar sus nodos y rutas sin consultas externas. No hay autenticación, sesión, escaneo, consultas a colectores ni llamadas a una IA.

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
  controllers/                Estado compartido del tema
  routes/                     Rutas de la aplicación
  services/                   Persistencia local de la preferencia visual
  pages/
    login/
      components/             Panel de presentación y formulario visual
      controller/             Navegación directa al dashboard
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
