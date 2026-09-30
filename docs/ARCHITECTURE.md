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

