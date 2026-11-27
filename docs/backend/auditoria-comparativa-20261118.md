# Auditoría comparativa de OSINT y Risk Score

Revisión del 18 de noviembre de 2026. Checkout: `fix/backend-corrections`, HEAD `af085dc`. Se consultaron Git, los contenedores existentes y Supabase en lectura. No se reconstruyeron ni reiniciaron contenedores, no se lanzaron consultas OSINT nuevas y no se cambiaron reglas, pesos, migraciones ni resultados remotos. El único arreglo funcional nuevo quedó en código local: respetar falsos positivos explícitos de SpiderFoot.

## Conclusión

La capacidad matemática de producir positivos sigue funcionando. La principal limitación actual es la falta de evidencia de servicios o CVE en las fuentes configuradas. Hubo una reducción real de módulos de SpiderFoot y la retirada de Shodan/Web; sus causas y efectos son diferentes. Los positivos históricos revisados no prueban una mejor detección pasiva: 41/60 contienen demostraciones y los dos 12 proceden de TLS activo. Existe una regresión intermedia de CVE en 1.1.0, ya recuperada por el código actual.

## 1. Identidad de las implementaciones

| Implementación | Evidencia disponible | Interpretación |
|---|---|---|
| Motor 1.0.0 | Git `2d2980d`, `6d52c91`; resultados de octubre | Código recuperable. Los pesos efectivos se reconstruyen desde la evidencia histórica, no desde el catálogo actual. |
| Reducción de módulos | Git `de4f25d`, incorporado por `588b782` | Sustituyó `usecase=Passive` por `sfp_dnsresolve,sfp_dnsraw,sfp_robtex,sfp_crobat_api`. |
| Motor 1.1.0 | Git `a239586`, integrado por `4c99839`; presente en HEAD `af085dc` | Corresponde al código versionado que describe la documentación aportada. CVE limitada a servicios. |
| Motor 1.2.0 | Seis puntajes cero en la organización | Etiqueta almacenada; no hay un commit local que permita reconstruir exactamente todo su código. |
| Motores 1.3.0 y 1.3.1 | Puntajes, observaciones y evidencia `CONF-006` | Revisiones con Web y persistencia. No hay commits locales de esas versiones. El campo de versión no identifica por sí solo la máquina ni todas las dependencias. |
| Motor 1.3.2 actual | Archivos modificados del checkout y contenedor `6d8ae5515d7e` | Coinciden las huellas SHA-256 normalizadas de motor, reglas, persistencia y orquestador antes del arreglo local de esta auditoría. |

La imagen existente fue creada el 17 de noviembre a las 10:55, hora de México. Su configuración leída ahora es: tres fuentes (`crt.sh`, `theHarvester`, `SpiderFoot`), theHarvester `certspotter,rapiddns,urlscan`, los cuatro módulos DNS anteriores y máximo 20 objetivos. No coincide con el contenedor 1.1.0 y `THEHARVESTER_SOURCES=crtsh` descrito en los adjuntos. No se puede atribuir ese otro contenedor a esta máquina con la información proporcionada.

La versión 1.3.2 se reutilizó para cambios de cobertura posteriores: la etiqueta no basta para reproducir un resultado. Las modificaciones están sin commit. Es necesario versionar código y registrar en futuros análisis commit/huella, imagen, configuración no secreta y versión del catálogo. No se fabricó retrospectivamente esa procedencia.

## 2. Qué cambió en la detección

| Área | Antes | Actual | Clasificación |
|---|---|---|---|
| SpiderFoot | Grupo Passive completo | Cuatro módulos DNS | Reducción real de cobertura potencial; no prueba que antes hubiera credenciales o resultados reales de puertos/CVE. |
| Shodan | Colector previsto; obtiene puertos, banners y CVE si hay permiso | Fuera del flujo activo por restricciones de plan | Capacidad condicionada retirada; no se reactivó. |
| Web | Comprobación HTTP/TLS directa en revisiones 1.3.0/1.3.1 | Fuera del flujo pasivo | Decisión explícita de alcance, no regresión que deba revertirse. |
| crt.sh | Certificados históricos podían puntuar con calibración original | CT informativa; CONF-001/002 inactivas y peso 0 | Corrección de interpretación: CT no prueba TLS servido. |
| Correos | IDEN-003 peso 5 | Peso 0, activa | Evita equiparar publicación con filtración. |
| CVE | 1.0.0 aceptaba activos variados; 1.1.0 restringió a servicio | Servicio, IP, dominio y subdominio; evita duplicado IP/servicio de la misma CVE | Regresión intermedia recuperada y probada. |
| Inventario | `run_all` original recibía solo el dominio | Lectura paginada, objetivos por tipo/alcance, expansión acotada y pendientes | Mejora respecto al backend antiguo. |
| Persistencia | Puntaje de observaciones de un escaneo | Consolida con último snapshot persistente elegible | Semántica más amplia, con límites descritos abajo. |

La fórmula de combinación no se sustituyó: `aporte=peso*(0.6+0.4*confianza)`; confianza base más 0.15 por fuente adicional, máximo 0.99; combinación por complemento multiplicativo, redondeo por categoría y después global. La severidad es una clasificación; la cifra procede del peso y confianza, no de multiplicar directamente por severidad.

## 3. Catálogo y evaluadores

| Regla | Peso histórico observado | Peso actual | Estado actual / condición |
|---|---:|---:|---|
| INFRA-001 | 20 | 15 | Activa; servicio TCP de administración remota, incluido SSH 22. |
| INFRA-002 | 30 | 30 | Activa; servicio TCP de base de datos, incluido PostgreSQL 5432. |
| INFRA-003 | 10 | 8 | Activa; CVE válida, asociada a activo, no marcada explícitamente no verificada; alcance IP/nombre comprobado al persistir. No demuestra explotabilidad. |
| IDEN-003 | 5 | 0 | Activa; correo público produce señal informativa. |
| CONF-001/002 | 15 / 8 | 0 / 0 | Inactivas; evaluadores históricos actuales dependen de Web. |
| CONF-006/007/008 | 12 / 4 / 6 | 12 / 4 / 6 | Inactivas por retirada de Web. La política también las excluye defensivamente. |
| INFRA-004, CONF-003/004/005, IDEN-001/002, FUGA-001/002/003/004 | Varios | Varios | Diez reglas inactivas sin evaluador. No basta activarlas en Supabase. |

Son 19 reglas remotas, cuatro activas y nueve evaluadores Python incluyendo los históricos. La calibración de `20261110000000_calibrar_reglas_riesgo.sql` redujo pesos y desactivó las diez reglas sin evaluador. Las cinco dependientes de Web se retiraron después. No se alteró ese catálogo en esta auditoría.

## 4. Reconstrucción de los positivos

| Escaneo | Motor / puntaje | Evidencia y aportes |
|---|---|---|
| `c3caebbc-8fc3-4173-846e-4ade292122ae` | 1.0.0 / 41 | SSH en `203.0.113.10` (17.6), dos correos públicos (4.6 y 4.9), CT `Demo CA` próxima a vencer (7.68) y expirada (14.4). |
| `7d7d7db8-f6c1-4b07-ae4a-1726dc75a160` | 1.0.0 / 60 | SSH (18.8), PostgreSQL documental (26.4), CVE-2018-15473 (8), dos correos y los certificados Demo CA anteriores. |
| `3b7ad36d-7a39-41b9-8e50-06b12b75115b` | 1.3.0 / 12 | `CONF-006`, www, TLS `verify_code=62`, aporte 11.52 redondeado a 12. Fuente Web. |
| `6342c726-4500-4303-b0f0-df9143d81cf5` | 1.3.1 / 12 | Mismo tipo de evidencia Web, otro escaneo/observación. |

Se reconstruyeron 41, 60, 12 y 12 usando sus aportes y agrupación histórica, sin escribir a Supabase. Los dos primeros contienen IP documental y certificados Demo CA: no acreditan servicios reales del cliente. Los dos últimos sí registran una comprobación TLS, pero fue activa y está fuera del alcance pasivo. No se importaron al riesgo vigente ni se borraron.

## 5. Trazado de los ceros y descartes

En `8e393528-a29f-4317-a705-11cd17968a62`, SpiderFoot produjo 10 observaciones de identificación y 8 resoluciones DNS. No hay eventos crudos de puerto o CVE en el desglose revisado. Se descartaron 400 eventos de tipos no soportados, conservados en el crudo: cohosting, afiliaciones, datos RIR y DNS del proveedor.

Ejemplos leídos: `DNS_SPF` contiene `v=spf1 -all` cuyo padre es **vercel.app**, no el dominio del cliente; `RAW_DNS_RECORDS` contiene NS de vercel.app; `AFFILIATE_INTERNET_NAME` apunta a `ns1.vercel-dns-3.com`; `CO_HOSTED_SITE` contiene sitios vecinos de Vercel. Puntuar estos datos como riesgos propios sería una atribución incorrecta. No se encontró una CVE o puerto real descartado que explique el cero de estos análisis. Sí existe pérdida de contexto informativo en la normalización, disponible todavía en el crudo; ampliar esa representación requiere preservar el padre/proveedor y no convertirlo automáticamente en riesgo.

crt.sh obtuvo cero en la consulta de sufijo y HTTP 404 en la exacta; theHarvester registró rate limiting de Cert Spotter. Sus filas `completado` con error significan respuesta parcial, no cobertura sana. El estado global es incompleto y el puntaje parcial. En `1b076fd0-e175-4a58-abb2-46aa7137eb04`, las tres fuentes terminaron sin incidencias finales y la cobertura de infraestructura es limitada: 18 activos inventariados, cuatro nombres consultados, nueve IPs y tres servicios fuera del alcance IP, dos correos sin consulta compatible. `completado` con `es_parcial=true` y fuentes faltantes vacías es explicable por esa cobertura; no es por sí solo corrupción.

Se evaluaron en memoria las observaciones guardadas de ambos escaneos con el catálogo actual: 0 y cero hallazgos, coincidiendo con Supabase. No se llamó a `calcular_y_guardar` ni a `guardar_riesgo`.

## 6. Hallazgos vigentes y riesgo de organización

`risk/persistencia.py` busca el último snapshot con `persistencia_hallazgos=true` de la organización y lleva adelante estados abierto/nuevo/revisado/aceptado. Deduplica por activo/regla, conserva evidencia original y marca lo arrastrado pendiente de revalidación. Excluye resuelto/falso positivo/descartado, retirado del riesgo, reglas inactivas y evidencia fuera del alcance actual. Las pruebas confirman arrastre positivo y reducción tras resolución.

Hay límites que impiden llamarlo un registro global completo: no importa automáticamente resultados anteriores a la línea base; no busca indefinidamente cada hallazgo perdido en snapshots posteriores; al cambiar el alcance, un hallazgo fuera del alcance nuevo puede dejar de arrastrarse; un recálculo histórico no reconstruye los snapshots posteriores. No se encontró en los casos revisados un hallazgo pasivo legítimo omitido que debiera elevar el cero. Los candidatos históricos positivos revisados son demostración o Web.

Propuesta, sin implementarla: conservar un puntaje inmutable por ejecución y un registro independiente de hallazgos vigentes de organización, identificado por activo/regla con evidencias fechadas y estado de resolución. Separar autorización para consultar de atribución/propiedad del activo; no borrar riesgo conocido solo porque una ejecución tenga alcance menor. Requiere diseño de migración, cuarentena de demostraciones, versionado de calibración y reglas de resolución/reapertura. No se debe sumar indiscriminadamente el historial.

## 7. Defecto corregido localmente y pruebas

SpiderFoot exporta `false_positive` en `sfwebui.py`; el normalizador de BaxterSec lo ignoraba. Una prueba con puerto marcado falso positivo seguía produciendo `servicio_expuesto`. Cuatro casos fallaron antes del arreglo. Ahora `backend/app/osint_normalization.py` descarta las marcas explícitas true/1 con motivo `falso_positivo_fuente`; conserva false/0/ausente. No cambia los crudos remotos ni produce hallazgos nuevos. Es un defecto de calidad de evidencia, no la causa de los ceros actuales. Se corrigieron también comentarios obsoletos en `risk/reglas.py`.

Comparación ejecutada con el código de Git 1.0.0, Git 1.1.0 y el actual, utilizando exactamente los mismos pesos actuales e inputs sintéticos, sin red:

| Caso | 1.0.0 | 1.1.0 | Actual |
|---|---:|---:|---:|
| DNS | 0 | 0 | 0 |
| SSH | 13 | 13 | 13 |
| PostgreSQL | 26 | 26 | 26 |
| CVE de servicio | 6 | 6 | 6 |
| CVE de subdominio | 6 | 0 | 6 |
| Correo público | 0 | 0 | 0 |

Suite completa: 183 pruebas y dos subtests aprobados. Incluye normalizador→motor, deduplicación, arrastre/resolución, alcance y expansión de objetivos. Dos avisos de dependencias existentes. El arreglo local no está dentro de la imagen en ejecución: desplegarlo requiere reconstrucción posteriormente autorizada.

## 8. Recuperación de cobertura pasiva

Primero debe conservarse una versión reproducible del código actual. Después puede ampliarse la evidencia de forma selectiva; restaurar indiscriminadamente el grupo Passive no garantiza datos ni permisos y puede reintroducir módulos lentos o defectuosos.

- Los módulos instalados `sfp_shodan` y `sfp_censys` declaran puertos/banners; requieren credenciales y compatibilidad de API. No están activados. Shodan sigue sin autorización para reactivarse.
- InternetDB ofrece datos públicos de IP (puertos, CPE y CVE) y API gratuita. Es una opción a evaluar, no una integración habilitada; pertenece a Shodan, exige revisar atribución y frescura, y una CVE derivada de CPE no confirma vulnerabilidad. [Documentación oficial](https://book.shodan.io/developer-apis/internetdb/).
- Censys Free ofrece consultas de activos con cuotas y permisos limitados; la API actual necesita revisión respecto al módulo antiguo instalado. [API oficial](https://docs.censys.com/reference/get-started), [créditos](https://docs.censys.com/docs/platform-credits-free-starter).
- urlscan permite buscar escaneos existentes: aprovechar datos ya publicados de tecnologías y recursos mantendría la consulta pasiva. Enviar una URL a escanear provocaría una nueva visita y no debe confundirse con búsqueda histórica. [API oficial](https://docs.urlscan.io/pages/api-intro).
- DNS/SPF/DMARC requiere evidencia atribuida al nombre correcto, consultas explícitas de los registros adecuados y semántica negativa comprobable. Que el crudo no contenga DMARC no prueba su ausencia. Las reglas correspondientes todavía no tienen evaluador.

Estas opciones son propuestas; no se añadieron herramientas ni claves y no se contactaron objetivos. Para el dominio de Vercel, ninguna fuente IP debe atribuir servicios de toda la plataforma al cliente por compartir resolución DNS.

## Archivos y evidencia

- `backend/app/orchestrators.py`, `main.py`, `scan_report.py`: selección, expansión y registro por objetivo.
- `backend/app/osint_normalization.py`: conversión y descartes; arreglo local de falsos positivos.
- `backend/app/risk/reglas.py`, `motor.py`, `persistencia.py`: condiciones, fórmula y arrastre.
- `backend/app/source_policy.py`: exclusión de fuentes/reglas retiradas.
- `backend/tests/test_risk_audit.py`: nuevas pruebas sin red.
- `auditoria-comparativa-20261118-evidencia.json`: lecturas de reglas, puntajes y casos, con resúmenes de crudos.
- `auditoria-comparativa-20261118-pruebas.json`: resultados comparativos de los tres motores.
- `validacion-cobertura-20261117.md`: prueba integrada previa y sus 18 activos; no fue repetida en esta auditoría.
