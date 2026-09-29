# BaxterSec

Plataforma OSINT para descubrir, organizar y visualizar información pública relacionada con la superficie de exposición de un dominio autorizado.

> Proyecto académico en desarrollo. Sólo se utilizarán fuentes públicas, APIs autorizadas y técnicas pasivas de recopilación.

## Objetivo

Construir una aplicación que permita:

- Analizar un dominio autorizado.
- Recopilar información desde diferentes fuentes OSINT.
- Normalizar y deduplicar los resultados.
- Identificar activos y posibles hallazgos.
- Calcular un nivel de riesgo trazable.
- Consultar los resultados mediante un dashboard.

## Tecnologías previstas

- **Frontend:** React, Vite y TypeScript.
- **Backend:** Python y FastAPI.
- **Base de datos:** PostgreSQL.
- **Entorno de desarrollo:** Docker y Docker Compose.
- **Despliegue del frontend:** Vercel.

## Estructura inicial

```text
TC3008AVJW/
├── backend/     # API, orquestación y procesamiento
├── frontend/    # Dashboard web
└── database/    # Migraciones y recursos de PostgreSQL
```

## Flujo de ramas

- main: versión estable y conectada a producción.
- dev: integración y pruebas antes de producción.
- feature/\*: desarrollo de nuevas funcionalidades.
- fix/_: corrección de errores.
  Los cambios deben enviarse mediante Pull Request:
  feature/_ → dev → main
  Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para conocer las reglas de colaboración.
  Estado del proyecto
  Actualmente se está preparando la estructura inicial del monorepo.
  Ejecución local
  Las instrucciones de instalación y ejecución se agregarán cuando estén configurados el frontend, el backend y Docker.

## Equipo

- Antonio Jesús Calderón Burgos
- Jaime Gámez Gómez-Rubalcava
- Valeria Pérez Mendoza
- Willian Salomon Lemus Sanchez

## Aviso de uso

Este proyecto está diseñado exclusivamente para fines académicos y defensivos. Los análisis deben realizarse únicamente sobre dominios propios, ficticios o expresamente autorizados.
