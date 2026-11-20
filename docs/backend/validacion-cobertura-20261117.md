# Validación de cobertura y reporte — 17 de noviembre de 2026

Análisis: `1b076fd0-e175-4a58-abb2-46aa7137eb04`. Inicio: 2026-11-17T16:55:46.818053+00:00. Fin: 2026-11-17T16:57:32.086049+00:00. Estado de consultas: completado. Risk Score: 0; parcial por limitaciones de cobertura: True.

El dominio raíz y api/dev/www se consultaron en el mismo análisis. crt.sh cubrió los subdominios mediante la búsqueda de sufijo CT. Las otras fuentes tienen una consulta registrada por nombre. Consultado no equivale a una evaluación integral de seguridad.

| Activo | Consultado | Fuentes y método | Observaciones | Hallazgos | Motivo o limitación |
|---|---|---|---:|---:|---|
| 203.0.113.10:22/tcp | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 216.198.79.131 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 64.29.17.3 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| www.receta-gastro-centro-app.vercel.app | Sí | crt.sh: consulta de sufijo CT; theHarvester: consulta de fuente; SpiderFoot: consulta de fuente | 3 | 0 | Limitada a indicadores públicos |
| ventas@receta-gastro-centro-app.vercel.app | No | Ninguna | 0 | 0 | Tipo sin consulta compatible en las fuentes configuradas |
| 216.198.79.3 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 203.0.113.10 | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 216.198.79.195 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 64.29.17.131 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 64.29.17.67 | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| contacto@receta-gastro-centro-app.vercel.app | No | Ninguna | 0 | 0 | Tipo sin consulta compatible en las fuentes configuradas |
| 203.0.113.10:5432/tcp | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| receta-gastro-centro-app.vercel.app | Sí | crt.sh: consulta de fuente; theHarvester: consulta de fuente; SpiderFoot: consulta de fuente | 3 | 0 | Limitada a indicadores públicos |
| 203.0.113.10:443/tcp | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| 64.29.17.195 | No | Ninguna | 1 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| api.receta-gastro-centro-app.vercel.app | Sí | crt.sh: consulta de sufijo CT; theHarvester: consulta de fuente; SpiderFoot: consulta de fuente | 3 | 0 | Limitada a indicadores públicos |
| 216.198.79.67 | No | Ninguna | 0 | 0 | Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor |
| dev.receta-gastro-centro-app.vercel.app | Sí | crt.sh: consulta de sufijo CT; theHarvester: consulta de fuente; SpiderFoot: consulta de fuente | 3 | 0 | Limitada a indicadores públicos |

## Fuentes

- crt.sh: completado; 0 observaciones; 0 activos nuevos. Sin incidencias finales.
- SpiderFoot: completado; 18 observaciones; 0 activos nuevos. Sin incidencias finales.
- theHarvester: completado; 0 observaciones; 0 activos nuevos. Sin incidencias finales.

Observaciones por tipo: {"descubierto": 10, "resuelve_a": 8}

Reglas evaluadas: IDEN-003, INFRA-001, INFRA-002, INFRA-003. No hubo hallazgos puntuables; no se alteraron los pesos. Las fuentes no aportaron evidencia de servicios o CVE en este análisis.

## Cambios y validación

La lectura inicial recorre todas las páginas del inventario. El presupuesto limita la ejecución, conserva los pendientes y evita ciclos y consultas duplicadas. El reporte y el riesgo se guardan en la misma RPC, dentro de cobertura; un recálculo conserva ese reporte. No se necesita migración de esquema.

El resumen incorpora vistas general, por herramienta, por activo y técnica, más selección de análisis anteriores. Reutiliza las respuestas originales de los popups de Fuentes. Los análisis anteriores sin trazabilidad muestran esa limitación.

Regresión: 169 pruebas y 2 subtests. TypeScript y ESLint sin errores. Compilación correcta con aviso de tamaño de paquetes. Verificación visual autenticada: vista general, herramientas, activos y motivo de exclusión de servicio.

