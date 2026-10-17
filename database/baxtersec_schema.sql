
-- =====================================================================
-- BaxterSec - Esquema de base de datos (PostgreSQL)
-- Generado a partir de "BaxterSec. Diagrama ER" (Lucidchart)
-- Requiere PostgreSQL 13+ (gen_random_uuid() es nativo)
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- 1. organizaciones
-- ---------------------------------------------------------------------
CREATE TABLE organizaciones (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre             text        NOT NULL,
    dominio_principal  text        NOT NULL UNIQUE,
    creado_en          timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 2. usuarios
-- ---------------------------------------------------------------------
CREATE TABLE usuarios (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organizacion_id  uuid        NOT NULL
                     REFERENCES organizaciones (id) ON DELETE CASCADE,
    nombre           text        NOT NULL,
    correo           text        NOT NULL UNIQUE,
    hash_contrasena  text        NOT NULL,
    rol              text        NOT NULL,
    esta_activo      boolean     NOT NULL DEFAULT true,
    ultimo_acceso   timestamptz NULL,
    creado_en        timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 3. autorizaciones_dominio
-- ---------------------------------------------------------------------
CREATE TABLE autorizaciones_dominio (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organizacion_id       uuid        NOT NULL
                          REFERENCES organizaciones (id) ON DELETE CASCADE,
    autorizado_por        uuid        NOT NULL
                          REFERENCES usuarios (id),
    alcance               text        NOT NULL,
    referencia_documento  text,
    autorizado_en         timestamptz NOT NULL DEFAULT now(),
    expira_en             timestamptz NULL,
    revocada_en           timestamptz NULL
);

-- ---------------------------------------------------------------------
-- 4. fuentes_osint
-- ---------------------------------------------------------------------
CREATE TABLE fuentes_osint (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre        text NOT NULL UNIQUE,
    tipo_acceso  text NOT NULL
);

-- ---------------------------------------------------------------------
-- 5. activos
-- ---------------------------------------------------------------------
CREATE TABLE activos (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organizacion_id    uuid        NOT NULL
                       REFERENCES organizaciones (id) ON DELETE CASCADE,
    tipo               text        NOT NULL,
    valor              text        NOT NULL,
    visto_primera_vez  timestamptz NOT NULL DEFAULT now(),
    visto_ultima_vez   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 6. reglas_riesgo
-- ---------------------------------------------------------------------
CREATE TABLE reglas_riesgo (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo       text        NOT NULL UNIQUE,
    nombre       text        NOT NULL,
    descripcion  text,
    tipo_activo  text,
    categoria    text        NOT NULL,
    severidad    text        NOT NULL,
    peso         int         NOT NULL DEFAULT 0,
    esta_activa  boolean     NOT NULL DEFAULT true,
    creado_en    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 7. escaneos
-- ---------------------------------------------------------------------
CREATE TABLE escaneos (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organizacion_id  uuid        NOT NULL
                     REFERENCES organizaciones (id) ON DELETE CASCADE,
    solicitado_por   uuid        NOT NULL
                     REFERENCES usuarios (id),
    autorizacion_id  uuid        NOT NULL
                     REFERENCES autorizaciones_dominio (id),
    estado           text        NOT NULL DEFAULT 'pendiente',
    iniciado_en      timestamptz NULL,
    finalizado_en    timestamptz NULL
);

-- ---------------------------------------------------------------------
-- 8. resultados_crudos
-- ---------------------------------------------------------------------
CREATE TABLE resultados_crudos (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id    uuid        NOT NULL
                  REFERENCES escaneos (id) ON DELETE CASCADE,
    fuente_id     uuid        NOT NULL
                  REFERENCES fuentes_osint (id),
    estado        text        NOT NULL,
    contenido     jsonb       NOT NULL,
    hash_contenido text       NOT NULL,
    observado_en  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX resultados_crudos_dedupe_idx
    ON resultados_crudos (escaneo_id, fuente_id, hash_contenido);

CREATE UNIQUE INDEX activos_organizacion_tipo_valor_idx
    ON activos (organizacion_id, tipo, valor);

-- ---------------------------------------------------------------------
-- 8b. observaciones normalizadas (evidencia previa a reglas de riesgo)
-- ---------------------------------------------------------------------
CREATE TABLE observaciones (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id          uuid        NOT NULL
                        REFERENCES escaneos (id) ON DELETE CASCADE,
    activo_id           uuid        NOT NULL
                        REFERENCES activos (id) ON DELETE CASCADE,
    fuente_id           uuid        NOT NULL
                        REFERENCES fuentes_osint (id),
    resultado_crudo_id  uuid        NOT NULL
                        REFERENCES resultados_crudos (id) ON DELETE CASCADE,
    atributo            text        NOT NULL
                        CHECK (atributo IN (
                            'descubierto', 'certificado', 'servicio_expuesto',
                            'resuelve_a', 'cve', 'info_host'
                        )),
    datos               jsonb       NOT NULL DEFAULT '{}'::jsonb
                        CHECK (jsonb_typeof(datos) = 'object'),
    observado_en        timestamptz NOT NULL DEFAULT now(),
    creado_en           timestamptz NOT NULL DEFAULT now(),
    datos_hash          text        GENERATED ALWAYS AS (md5(datos::text)) STORED,
    UNIQUE (escaneo_id, activo_id, fuente_id, atributo, datos_hash)
);

CREATE INDEX observaciones_escaneo_idx ON observaciones (escaneo_id);
CREATE INDEX observaciones_activo_idx ON observaciones (activo_id);
CREATE INDEX observaciones_fuente_idx ON observaciones (fuente_id);

-- ---------------------------------------------------------------------
-- 8a. resultados_fuentes: estado independiente de cada proveedor OSINT
-- ---------------------------------------------------------------------
CREATE TABLE resultados_fuentes (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id           uuid        NOT NULL
                         REFERENCES escaneos (id) ON DELETE CASCADE,
    fuente_id            uuid        NOT NULL
                         REFERENCES fuentes_osint (id),
    estado               text        NOT NULL DEFAULT 'pendiente'
                         CHECK (estado IN ('pendiente', 'ejecutando', 'completado', 'fallido')),
    iniciado_en          timestamptz NULL,
    finalizado_en        timestamptz NULL,
    error                text        NULL,
    resultado_crudo_id   uuid        NULL
                         REFERENCES resultados_crudos (id) ON DELETE SET NULL,
    ya_procesado         boolean     NOT NULL DEFAULT false,
    observaciones_generadas integer  NOT NULL DEFAULT 0,
    activos_nuevos       integer     NOT NULL DEFAULT 0,
    activos_existentes   integer     NOT NULL DEFAULT 0,
    observaciones_nuevas integer     NOT NULL DEFAULT 0,
    observaciones_duplicadas integer NOT NULL DEFAULT 0,
    descartadas          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (escaneo_id, fuente_id)
);

-- ---------------------------------------------------------------------
-- 9. hallazgos
-- ---------------------------------------------------------------------
CREATE TABLE hallazgos (
    id          uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id  uuid    NOT NULL
                REFERENCES escaneos (id) ON DELETE CASCADE,
    activo_id   uuid    NOT NULL
                REFERENCES activos (id),
    fuente_id   uuid    NOT NULL
                REFERENCES fuentes_osint (id),
    regla_id    uuid    NULL
                REFERENCES reglas_riesgo (id),
    categoria   text    NOT NULL,
    severidad   text    NOT NULL,
    confianza   numeric NOT NULL,
    estado      text    NOT NULL DEFAULT 'abierto',
    evidencia   jsonb
);

-- ---------------------------------------------------------------------
-- 10. explicaciones_ia
-- ---------------------------------------------------------------------
CREATE TABLE explicaciones_ia (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id   uuid        NOT NULL
                 REFERENCES escaneos (id) ON DELETE CASCADE,
    hallazgo_id  uuid        NULL
                 REFERENCES hallazgos (id) ON DELETE CASCADE,
    contenido    text        NOT NULL,
    creado_en    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 11. puntajes_riesgo
-- ---------------------------------------------------------------------
CREATE TABLE puntajes_riesgo (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    escaneo_id         uuid NOT NULL
                       REFERENCES escaneos (id) ON DELETE CASCADE,
    puntaje_global     int  NOT NULL,
    infraestructura    int  NOT NULL,
    identidad_digital  int  NOT NULL,
    configuracion      int  NOT NULL,
    fuga_de_datos      int  NOT NULL
);

-- ---------------------------------------------------------------------
-- 12. bitacora_auditoria
-- ---------------------------------------------------------------------
CREATE TABLE bitacora_auditoria (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id       uuid        NULL
                     REFERENCES usuarios (id) ON DELETE SET NULL,
    organizacion_id  uuid        NULL
                     REFERENCES organizaciones (id) ON DELETE SET NULL,
    accion           text        NOT NULL,
    entidad          text        NOT NULL,
    entidad_id       uuid        NULL,
    detalle          jsonb       NULL,
    ip               inet        NULL,
    creado_en        timestamptz NOT NULL DEFAULT now()
);

-- =====================================================================
-- Índices sobre llaves foráneas (PostgreSQL no los crea automáticamente)
-- =====================================================================
CREATE INDEX idx_usuarios_organizacion        ON usuarios (organizacion_id);
CREATE INDEX idx_autorizaciones_organizacion  ON autorizaciones_dominio (organizacion_id);
CREATE INDEX idx_autorizaciones_autorizado    ON autorizaciones_dominio (autorizado_por);
CREATE INDEX idx_activos_organizacion         ON activos (organizacion_id);
CREATE INDEX idx_escaneos_organizacion        ON escaneos (organizacion_id);
CREATE INDEX idx_escaneos_solicitado_por      ON escaneos (solicitado_por);
CREATE INDEX idx_escaneos_autorizacion        ON escaneos (autorizacion_id);
CREATE INDEX idx_resultados_escaneo           ON resultados_crudos (escaneo_id);
CREATE INDEX idx_resultados_fuente            ON resultados_crudos (fuente_id);
CREATE INDEX idx_resultados_fuentes_escaneo   ON resultados_fuentes (escaneo_id);
CREATE INDEX idx_hallazgos_escaneo            ON hallazgos (escaneo_id);
CREATE INDEX idx_hallazgos_activo             ON hallazgos (activo_id);
CREATE INDEX idx_hallazgos_fuente             ON hallazgos (fuente_id);
CREATE INDEX idx_hallazgos_regla              ON hallazgos (regla_id);
CREATE INDEX idx_explicaciones_escaneo        ON explicaciones_ia (escaneo_id);
CREATE INDEX idx_explicaciones_hallazgo       ON explicaciones_ia (hallazgo_id);
CREATE INDEX idx_puntajes_escaneo             ON puntajes_riesgo (escaneo_id);
CREATE INDEX idx_bitacora_usuario             ON bitacora_auditoria (usuario_id);
CREATE INDEX idx_bitacora_organizacion        ON bitacora_auditoria (organizacion_id);

COMMIT;