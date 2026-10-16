-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.organizaciones (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nombre text NOT NULL,
  dominio_principal text NOT NULL UNIQUE,
  creado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT organizaciones_pkey PRIMARY KEY (id)
);
CREATE TABLE public.usuarios (
  id uuid NOT NULL,
  organizacion_id uuid,
  nombre text NOT NULL,
  correo text NOT NULL UNIQUE,
  rol text NOT NULL DEFAULT 'lector'::text CHECK (rol = ANY (ARRAY['admin'::text, 'analista'::text, 'lector'::text])),
  esta_activo boolean NOT NULL DEFAULT true,
  ultimo_acceso timestamp with time zone,
  creado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT usuarios_pkey PRIMARY KEY (id),
  CONSTRAINT usuarios_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id),
  CONSTRAINT usuarios_organizacion_id_fkey FOREIGN KEY (organizacion_id) REFERENCES public.organizaciones(id)
);
CREATE TABLE public.autorizaciones_dominio (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  organizacion_id uuid NOT NULL,
  autorizado_por uuid NOT NULL,
  alcance text NOT NULL,
  referencia_documento text,
  autorizado_en timestamp with time zone NOT NULL DEFAULT now(),
  expira_en timestamp with time zone,
  revocada_en timestamp with time zone,
  CONSTRAINT autorizaciones_dominio_pkey PRIMARY KEY (id),
  CONSTRAINT autorizaciones_dominio_organizacion_id_fkey FOREIGN KEY (organizacion_id) REFERENCES public.organizaciones(id),
  CONSTRAINT autorizaciones_dominio_autorizado_por_fkey FOREIGN KEY (autorizado_por) REFERENCES public.usuarios(id)
);
CREATE TABLE public.fuentes_osint (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nombre text NOT NULL UNIQUE,
  tipo_acceso text NOT NULL,
  CONSTRAINT fuentes_osint_pkey PRIMARY KEY (id)
);
CREATE TABLE public.activos (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  organizacion_id uuid NOT NULL,
  tipo text NOT NULL,
  valor text NOT NULL,
  visto_primera_vez timestamp with time zone NOT NULL DEFAULT now(),
  visto_ultima_vez timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT activos_pkey PRIMARY KEY (id),
  CONSTRAINT activos_organizacion_id_fkey FOREIGN KEY (organizacion_id) REFERENCES public.organizaciones(id)
);
CREATE TABLE public.reglas_riesgo (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  codigo text NOT NULL UNIQUE,
  nombre text NOT NULL,
  descripcion text,
  tipo_activo text,
  categoria text NOT NULL,
  severidad text NOT NULL,
  peso integer NOT NULL DEFAULT 0,
  esta_activa boolean NOT NULL DEFAULT true,
  creado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT reglas_riesgo_pkey PRIMARY KEY (id)
);
CREATE TABLE public.escaneos (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  organizacion_id uuid NOT NULL,
  solicitado_por uuid NOT NULL,
  autorizacion_id uuid NOT NULL,
  estado text NOT NULL DEFAULT 'pendiente'::text,
  iniciado_en timestamp with time zone,
  finalizado_en timestamp with time zone,
  CONSTRAINT escaneos_pkey PRIMARY KEY (id),
  CONSTRAINT escaneos_organizacion_id_fkey FOREIGN KEY (organizacion_id) REFERENCES public.organizaciones(id),
  CONSTRAINT escaneos_solicitado_por_fkey FOREIGN KEY (solicitado_por) REFERENCES public.usuarios(id),
  CONSTRAINT escaneos_autorizacion_id_fkey FOREIGN KEY (autorizacion_id) REFERENCES public.autorizaciones_dominio(id)
);
CREATE TABLE public.resultados_crudos (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  escaneo_id uuid NOT NULL,
  fuente_id uuid NOT NULL,
  estado text NOT NULL,
  contenido jsonb NOT NULL,
  observado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT resultados_crudos_pkey PRIMARY KEY (id),
  CONSTRAINT resultados_crudos_escaneo_id_fkey FOREIGN KEY (escaneo_id) REFERENCES public.escaneos(id),
  CONSTRAINT resultados_crudos_fuente_id_fkey FOREIGN KEY (fuente_id) REFERENCES public.fuentes_osint(id)
);
CREATE TABLE public.hallazgos (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  escaneo_id uuid NOT NULL,
  activo_id uuid NOT NULL,
  fuente_id uuid NOT NULL,
  regla_id uuid,
  categoria text NOT NULL,
  severidad text NOT NULL,
  confianza numeric NOT NULL,
  estado text NOT NULL DEFAULT 'abierto'::text,
  evidencia jsonb,
  CONSTRAINT hallazgos_pkey PRIMARY KEY (id),
  CONSTRAINT hallazgos_escaneo_id_fkey FOREIGN KEY (escaneo_id) REFERENCES public.escaneos(id),
  CONSTRAINT hallazgos_activo_id_fkey FOREIGN KEY (activo_id) REFERENCES public.activos(id),
  CONSTRAINT hallazgos_fuente_id_fkey FOREIGN KEY (fuente_id) REFERENCES public.fuentes_osint(id),
  CONSTRAINT hallazgos_regla_id_fkey FOREIGN KEY (regla_id) REFERENCES public.reglas_riesgo(id)
);
CREATE TABLE public.explicaciones_ia (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  escaneo_id uuid NOT NULL,
  hallazgo_id uuid,
  contenido text NOT NULL,
  creado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT explicaciones_ia_pkey PRIMARY KEY (id),
  CONSTRAINT explicaciones_ia_escaneo_id_fkey FOREIGN KEY (escaneo_id) REFERENCES public.escaneos(id),
  CONSTRAINT explicaciones_ia_hallazgo_id_fkey FOREIGN KEY (hallazgo_id) REFERENCES public.hallazgos(id)
);
CREATE TABLE public.puntajes_riesgo (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  escaneo_id uuid NOT NULL,
  puntaje_global integer NOT NULL,
  infraestructura integer NOT NULL,
  identidad_digital integer NOT NULL,
  configuracion integer NOT NULL,
  fuga_de_datos integer NOT NULL,
  CONSTRAINT puntajes_riesgo_pkey PRIMARY KEY (id),
  CONSTRAINT puntajes_riesgo_escaneo_id_fkey FOREIGN KEY (escaneo_id) REFERENCES public.escaneos(id)
);
CREATE TABLE public.bitacora_auditoria (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  usuario_id uuid,
  organizacion_id uuid,
  accion text NOT NULL,
  entidad text NOT NULL,
  entidad_id uuid,
  detalle jsonb,
  ip inet,
  creado_en timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT bitacora_auditoria_pkey PRIMARY KEY (id),
  CONSTRAINT bitacora_auditoria_organizacion_id_fkey FOREIGN KEY (organizacion_id) REFERENCES public.organizaciones(id),
  CONSTRAINT bitacora_auditoria_usuario_id_fkey FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id)
);