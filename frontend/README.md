# Frontend de BaxterSec

Prototipo navegable con React, Vite y TypeScript. El acceso conserva la composición de `feature/login` y siempre usa **Negative Zone**. El panel reproduce la estructura del dashboard de la propuesta visual y permite cambiar a **Kirby Print**.

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
- `/home/activos`: inventario con búsqueda y filtro por tipo.
- `/home/relaciones`: vínculos entre el dominio ficticio y sus subdominios.
- `/home/fuentes`: colectores previstos, aún sin conexión.
- `/home/hallazgos`: hallazgos con filtro por severidad.
- `/home/historial`: estado vacío hasta que existan análisis reales.
- `/home/asistente`: respuestas ilustrativas predefinidas.
- `/home/configuracion`: selección de tema Negative Zone o Kirby Print.

Los datos de `src/pages/dashboard/services/demoData.ts` se basan en `backend/mock_data.json`. La serie temporal y el desglose del puntaje en `screens/overview/services/overviewMock.ts` son valores ilustrativos para la maqueta. No hay autenticación, sesión, escaneo, consultas a colectores ni llamadas a una IA.

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
      components/             Navegación, cabecera, paletas y diálogo
      services/               Escenario ficticio compartido
      screens/
        overview/
          components/         Tarjetas y gráfica del resumen
          services/           Series y cifras ilustrativas
        assets/               Inventario y sus filtros
        relations/            Relaciones de muestra
        sources/              Fuentes previstas
        findings/             Hallazgos y filtro de severidad
        history/              Estado vacío de historial
        assistant/            Respuestas preparadas
        settings/             Selección de tema
      DashboardPage.tsx
      dashboard.css
```

Cada vista del panel está aislada en su carpeta. Los componentes del resumen y del login viven junto a su pantalla; los elementos que comparten varias vistas permanecen en `dashboard/components`.
