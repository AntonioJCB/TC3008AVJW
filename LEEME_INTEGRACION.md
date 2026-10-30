# BaxterSec · Integración del motor OSINT + riesgo

Este paquete **se copia encima de tu repositorio** (las rutas ya coinciden):

| Carpeta | Qué contiene |
|---|---|
| `backend/` | Tu backend con los arreglos, el motor de riesgo y los endpoints nuevos |
| `database/` | 1 migración nueva + script para preparar una organización de prueba |
| `frontend-next/` | Frontend Next.js (App Router) ya conectado a la API |

## 0. Antes de empezar

- Trabaja en una rama `feature/...` **creada desde `dev`**, y abre el PR hacia **`dev`** (no a `main`: tu CI lo rechaza).
- Nunca subas `.env`. Este paquete no trae ninguno.

```bash
git checkout dev && git pull
git checkout -b feature/motor-riesgo
```

## 1. Copiar los archivos y revisar el cambio

```bash
# desde la raíz del repo, ajusta la ruta del zip
unzip -o ~/Downloads/baxtersec-integracion.zip -d /tmp/baxtersec && cp -R /tmp/baxtersec/baxtersec-integracion/* .
git status
git diff backend/app/main.py backend/app/orchestrators.py   # revisa los cambios
```

## 2. Base de datos

La migración nueva va **después** de las tuyas (`20261016211140_...`):

```bash
cd database
supabase db push --dry-run     # debe listar SOLO 20261017120000_motor_de_riesgo.sql
supabase db push
```

Qué hace: estados válidos del escaneo, `UNIQUE` en hallazgos, columnas `es_parcial / fuentes_faltantes / cobertura` en `puntajes_riesgo`, y la función `guardar_riesgo()` (escritura atómica).
Las restricciones nuevas son `NOT VALID`: no revisan filas antiguas. Cuando confirmes que no hay estados raros: `ALTER TABLE escaneos VALIDATE CONSTRAINT escaneos_estado_check;`

## 3. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # llena SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SHODAN_API_KEY...
pytest                          # 76 pasan, 9 se omiten (necesitan base de datos)
uvicorn app.main:app --reload --port 8000
```

- Ejecútalo con **un solo worker** (`--workers 1`, el valor por defecto): los escaneos corren en segundo plano dentro del proceso.
- Documentación interactiva de la API: http://localhost:8000/docs

## 4. Preparar datos de prueba

1. Regístrate en el frontend (paso 5) con tu correo.
2. En Supabase → SQL Editor, abre `database/scripts/bootstrap_demo.sql`, cambia **correo** y **dominio** y ejecútalo. Crea tu organización (eres `admin`) y una autorización cuyo `alcance` contiene el dominio.
3. **Solo escanees dominios tuyos o con permiso escrito.**

## 5. Frontend

```bash
cd frontend-next
cp .env.local.example .env.local   # URL de la API + URL y clave PÚBLICA de Supabase
npm install
npm run dev                        # http://localhost:3000
```

Flujo: login → *Nuevo escaneo* → se crea y ejecuta (responde al instante) → la página sigue el avance cada 3 s y muestra **qué fuente falló y cuáles no**, el riesgo (parcial si faltó una fuente) y los hallazgos.

> Tu README dice React + Vite. Esta carpeta es un proyecto Next.js **aparte** (`frontend-next/`) para no pisar el trabajo de tu equipo. Si se quedan con Vite, copia `src/lib`, `src/hooks` y `src/components`: no dependen de Next.

## 6. Probar las fuentes reales (una a una, con un dominio tuyo)

| Fuente | Qué necesita |
|---|---|
| crt.sh | Nada (reintenta 3 veces si falla) |
| Shodan | `SHODAN_API_KEY`. Usa `/dns/resolve` + `/shodan/host/{ip}`. Comprueba tu plan: `curl "https://api.shodan.io/api-info?key=TU_KEY"` |
| theHarvester | Instalado y en el PATH (`THEHARVESTER_BIN`). Revisa los nombres de `THEHARVESTER_SOURCES` con `theHarvester -h` |
| SpiderFoot | Servidor corriendo: `python sf.py -l 127.0.0.1:5001` |

Si una falla **no pasa nada grave**: el escaneo queda `incompleto`, el mensaje dice cuál falló y el riesgo se marca parcial.

## 7. Prueba de integración contra tu Supabase de DESARROLLO (opcional)

Escribe datos reales: usa un proyecto de desarrollo, nunca producción. Las fuentes externas se simulan.

```bash
export BAXTERSEC_TEST_POSTGREST_URL=https://TU-PROYECTO.supabase.co/rest/v1
export BAXTERSEC_TEST_SERVICE_KEY=...          # service_role (solo en tu terminal)
export BAXTERSEC_TEST_USER_ID=...              # ids que imprime bootstrap_demo.sql
export BAXTERSEC_TEST_AUTORIZACION_ID=...
pytest tests/test_integracion_postgrest.py -v
```

## 8. Calibrar el riesgo (sin tocar código)

Cada hallazgo aporta `peso × (0.6 + 0.4 × confianza)` y los aportes se combinan con rendimientos decrecientes (máx. 100). El `peso` y la `severidad` viven en `reglas_riesgo`:

```sql
UPDATE reglas_riesgo SET peso = 40 WHERE codigo = 'INFRA-002';
```
Luego `POST /api/escaneos/{id}/riesgo/recalcular` (o el botón *Recalcular riesgo*). Recalcular **conserva** el estado que un analista haya puesto a un hallazgo.

Hoy se evalúan **6 de 16 reglas** (INFRA-001/002/003, CONF-001/002, IDEN-003). El resto necesita fuentes que no están (DNS/SPF/DMARC, filtraciones, repositorios). La cobertura se muestra siempre: una regla no evaluada **no** significa "sin problemas".

## 9. Antes de desplegar (pendiente)

- Las rutas validan la sesión con Supabase (`auth.get_user`), pero `organizacion_id`/`usuario_id` salen de la base, no del cliente: bien. Falta revisar límites de peticiones (rate limiting) y HTTPS.
- Los escaneos viven en memoria del proceso. Para varios workers o más carga, mover a una cola (Celery/RQ/Arq). Al arrancar, la API cierra escaneos que quedaron "ejecutando" tras un reinicio.
- Rota cualquier llave que hayas compartido fuera de tu equipo (`SERVICE_ROLE_KEY`, `SHODAN_API_KEY`).
