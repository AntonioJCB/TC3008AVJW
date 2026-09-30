# Documentación de Arquitectura del Sistema - BaxterSec

## 1. Estructura del Proyecto y Entorno
El proyecto está estructurado como un monorrepositorio organizado en el directorio raíz `TC3008AVJW/`:

```text
TC3008AVJW/
├── backend/     # API, orquestación OSINT, procesamiento y motor de riesgo
├── frontend/    # Dashboard web interactivo
└── database/    # Migraciones y scripts de soporte para PostgreSQL

```
## 2. Entorno y Despliegue

* **Entorno de Desarrollo Local:** Orquestado mediante **Docker** y **Docker Compose** para garantizar ambientes de ejecución homogéneos.
* **Despliegue de Frontend:** Alojado y desplegado en **Vercel**.
* **Estrategia de Control de Versiones:** Modelo de branching con ramas `main`, `dev`, `feature/*` y `fix/*`, requiriendo Pull Requests para la integración continuo-progresiva (`feature/` → `dev` → `main`).

## 3. Componentes y Responsabilidades
### A.Capa de Presentación
* Tecnologías: React/componentes web UI
* Esta capa permitirá al usuario enviar un dominio autorizado para iniciar el escaneo.
* La visualización estará centralizada en Global Risk Score (0-100) y desglose por categorías.
* Mostrará el inventario detallado de activos descubiertos (dominios, sudbominios, IPs públicas, correos corporativos, certificados SSL/TLS y servicios).
* Presentará una lista de Findings ordenados por severidad, origen y confianza.
* Interfaz de conversación/interacción con el asistente de IA explicativa.

### B.Capa de Servicios y API
* Tecnologías: FastApi, Python, SQLAlchemy
* Exposición de endpoints REST API/JSON consumidos por el cliente en React/Vite.
* Gestión segura de claves secretas y API Keys únicamente desde las variables de entorno del servidor.
* Orquestación de peticiones hacia el módulo de IA explicativa.
* Persistencia e intercambio de información con PostgreSQL a través de ORM.

### C. Orquestador y Colectores OSINT
* Tecnologías: Python, integración CLI y Rest APIs.
#### Ejecutar en paralelo y de manera aislada los recolectores OSINT pasivos autorizados:
* crt.sh: Consulta HTTP para descubrimiento de subdominios a través de certificados SSL/TLS.
* theHarvester: Ejecución via CLI para descubrir correos corporativos y subdominios.
* SpiderFoot: Interacción via API/CLI para recolección automatizada amplia.
* Shodan: Consultas via API REST para identificar puertos y servicios expuestos.

### D. Motor de Procesamiento, Correlación y Riesgo
* Tecnologías: Python
#### Responsabilidades
* Normalización: Estandarizar la estructura de los datos sin importar de cuál fuente OSINT provinieron.
* Deduplicación: Consolidar múltiples registros sobre la misma entidad en un único activo con trazabilidad de sus orígenes.
* Correlación: Mapear la relación jerárquica entre dominios, subdominios, IPs, certificados y correos.
* Cálculo de Risk Score: Calcular la puntuación de 0 a 100 utilizando reglas de negocio trazables y deterministas.

### E. Base de Datos
* Tecnologías: PostgreSQL
* Guardar los registros de datos crudos recolectados para auditoría y trazabilidad.
* Almacenar el inventario normalizado de activos `Assets`, hallazgos `Findings`, métricas y evaluaciones `Scores`.

### F. Capa de Inteligencia Artificial
* Tecnologías: Integración con modelos de lenguaje `Gemini`
* Explicar de manera clara en lenguaje natural las razones detrás del incremento o nivel de riesgo.
* Sugerir prioridades de remediación y apoyar en la generación de reportes ejecutivos para los analistas.

## 4. Flujo de Datos del Sistema
```text
[Usuario / Dashboard]
       │  
       │  1. Ingresa Dominio 
       ▼
[FastAPI Backend] 
       │
       │  2. Invocación de Análisis
       ▼
[Orquestador OSINT] ──► Ejecuta colectores en paralelo crt.sh, theHarvester, SpiderFoot, Shodan
       │
       │  3. Devuelve resultados crudos
       ▼
[Procesamiento & Correlación] 
       ├─► Normalización & Deduplicación
       ├─► Generación de Activos y Hallazgos
       └─► Cálculo determinista de Risk Score (0-100)
       │
       │  4. Guarda Activos, Hallazgos e Histórico
       ▼
[PostgreSQL Database]
       │
       │  5. Envía resumen de hallazgos para interpretación
       ▼
IA / LLM (BaxterSec AI Insights) ──► Genera explicaciones y recomendaciones
       │
       │  6. Devuelve respuesta enriquecida
       ▼
[FastAPI Backend] ──► 7. Respuesta consolidada  ──► React Dashboard
```

## 5. Text Stack
