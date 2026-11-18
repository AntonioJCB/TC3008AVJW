# Ejecutar BaxterSec: Docker y frontend Vite

Guía del checkout revisado el 18 de noviembre de 2026. Lee primero el
[diagnóstico de versiones](01-funcionamiento-y-diagnostico.md): los puntajes de
Supabase provienen también de motores posteriores al código local. Esta guía
documenta comandos de operación; no autoriza por sí sola reconstrucciones,
migraciones ni cambios de configuración en un entorno compartido.

## 1. Requisitos y carpetas

- Docker Desktop con contenedores Linux, abierto y con el motor listo.
- Node.js compatible con el `engines` de la versión de Vite instalada y npm.
- Acceso al proyecto Supabase de desarrollo acordado por el equipo.
- Sesión de usuario activa, organización activa y autorización vigente.
- Trabajar desde la raíz `TC3008AVJW`.

La interfaz actual es `frontend/`, React/Vite. La app de `database/` es auxiliar;
las instrucciones antiguas de `frontend-next/` no corresponden a este checkout.
No es necesario instalar manualmente `tools/` para usar Docker.

```bash
cd /ruta/a/TC3008AVJW
docker version
docker compose version
docker compose config --quiet
```

En macOS, si el daemon no responde, abre Docker Desktop. `config --quiet` valida
sin imprimir las credenciales resueltas; evita compartir `docker compose config`
sin `--quiet`, que puede mostrar secretos del entorno.

## 2. Revisar configuración del backend

Si existe `backend/.env`, consérvalo. Para una instalación nueva toma como modelo
`backend/.env.example` y rellena los valores locales sin subir el archivo a Git.

```dotenv
SUPABASE_URL=https://TU-PROYECTO.supabase.co
SUPABASE_SERVICE_ROLE_KEY=TU_JWT_LEGACY_SERVICE_ROLE
SHODAN_API_KEY=TU_LLAVE_SI_TIENES_ACCESO
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
FRONTEND_URL=http://localhost:5173
```

El SDK Python fijado es 2.15.3; la configuración actual exige llave legacy
`service_role`. Una publicable no es válida para esa variable. La publicable
del navegador y la privilegiada deben ser del mismo proyecto. No incluyas
`/rest/v1` en `SUPABASE_URL`.

Compose sobrescribe estas dos variables dentro del contenedor:

```text
THEHARVESTER_BIN=/opt/theHarvester/.venv/bin/theHarvester
SPIDERFOOT_URL=http://spiderfoot:5001
```

Los tiempos, fuentes internas de theHarvester y módulos de SpiderFoot salen del
entorno. La configuración actual puede consultar correctamente sin producir
ninguna señal puntuable. Revisa el diagnóstico antes de cambiar esos parámetros.

`BAXTERSEC_DATABASE_URL` solo corresponde al chequeo PostgreSQL directo opcional;
no sustituye las variables de Supabase del flujo de escaneo.

## 3. Usar contenedores existentes

```bash
docker compose ps
docker compose images
docker compose up -d --no-build
docker compose ps
```

`up` puede recrear contenedores si cambió la configuración y el backend puede
cerrar trabajos antiguos atascados durante su arranque. No reinicies durante
un análisis en curso. Para la revisión se abrió Docker Desktop y se usaron
los contenedores existentes, sin reconstruir imágenes.

En una instalación nueva sin imágenes se necesita construir, pero primero
asegura que este checkout sea la versión de backend que deseas ejecutar:

```bash
docker compose build
docker compose up -d
```

Este paso descarga herramientas y dependencias. No lo hagas para tratar de
«reparar» automáticamente la diferencia entre puntajes 1.3.2 y código 1.1.0.

## 4. Comprobar salud y herramientas

```bash
curl -fsS http://127.0.0.1:8000/health
docker compose exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://spiderfoot:5001/', timeout=10).status)"
docker compose exec backend /opt/theHarvester/.venv/bin/theHarvester -h
docker compose exec backend python -c "from app.risk.motor import VERSION_MOTOR; print(VERSION_MOTOR)"
```

En PowerShell puedes sustituir `curl` por `curl.exe`, o usar
`Invoke-RestMethod http://127.0.0.1:8000/health`.

Direcciones:

| Servicio | Dirección |
|---|---|
| FastAPI | http://127.0.0.1:8000 |
| Swagger | http://127.0.0.1:8000/docs |
| SpiderFoot | http://127.0.0.1:5001 |
| Frontend | http://localhost:5173 o la URL anunciada por Vite |

`/health` confirma proceso. SpiderFoot HTTP y `theHarvester -h` confirman
accesibilidad/instalación, no que los proveedores externos hayan respondido.

## 5. Preparar frontend

En otra terminal:

```bash
cd /ruta/a/TC3008AVJW/frontend
npm ci
```

Para una instalación nueva crea `frontend/.env` con:

```dotenv
VITE_SUPABASE_URL=https://TU-PROYECTO.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_TU_LLAVE_PUBLICA
VITE_API_URL=http://localhost:8000
```

No uses variables `NEXT_PUBLIC_*`: esta app es Vite. La plantilla
`frontend/.env.example` figuraba eliminada en el estado de trabajo durante la
revisión; no dependas de copiar un archivo que podría faltar. No se restauró
porque el usuario pidió no modificar el proyecto.

```bash
npm run dev
```

Abre la URL anunciada. Si Vite cambia a otro puerto, el origen debe estar
permitido en CORS; no cambies el puerto sin revisar también la configuración.
Reinicia Vite tras editar sus variables. El backend se configura al crear el
contenedor: editar `.env` no actualiza mágicamente un proceso ya arrancado.

## 6. Entrar a la aplicación

1. Abre `/login` y entra con una cuenta existente o invitada.
2. Si no tiene contraseña, usa el flujo de invitación/recuperación habilitado.
3. Un administrador de plataforma entra a `/admin`; el cliente a `/home`.
4. La cuenta del cliente necesita `usuarios.esta_activo=true`, organización
   activa y rol apropiado para iniciar análisis.
5. La organización necesita autorización vigente que incluya su dominio principal
   explícitamente. La API toma el dominio de la organización, no de texto libre.

La configuración de Supabase Auth debe permitir la URL de
`/restablecer-clave`, coherente con `FRONTEND_URL`.

Preparar un cliente, invitar o editar reglas modifica la base. Para una revisión
de lectura usa una cuenta y datos existentes. No ejecutes scripts antiguos de
bootstrap o seed sobre una base compartida sin comparar primero su estado.

## 7. Desarrollo de base y despliegue

Las migraciones están en `database/supabase/migrations`. No se aplican
automáticamente al levantar Compose. La base conectada puede tener cambios que
este checkout no incluye. Antes de cualquier migración: comparar versiones,
respaldar según el procedimiento del equipo y revisar el historial remoto.
Descubre los comandos de la versión instalada mediante `supabase --help` en vez
de copiar instrucciones de una versión diferente del CLI.

Para comprobar el frontend sin alterar dependencias:

```bash
npm run lint
npx tsc --noEmit --incremental false -p tsconfig.app.json
npx tsc --noEmit --incremental false -p tsconfig.node.json
```

`npm run build` genera `dist/`; `npm run preview` sirve ese build. En Vercel
configura las mismas variables públicas con una URL HTTPS real del backend.
Comprueba enlaces directos a `/home` y `/restablecer-clave`; el `vercel.json`
local estaba vacío y no demuestra por sí solo que haya fallback SPA.

## 8. Operación y parada

```bash
docker compose logs --tail=100 backend spiderfoot
docker compose stop
```

En la terminal de Vite, Ctrl+C. No compartas logs sin revisar su contenido.
`docker compose down` retira contenedores/red pero conserva el volumen por
defecto; `down -v` elimina datos de SpiderFoot. Supabase es externo a Compose.
No hay reanudación durable de tareas: no parar ni reconstruir a mitad del escaneo.

Para probar cada función continúa con [03-probar-funciones.md](03-probar-funciones.md).
