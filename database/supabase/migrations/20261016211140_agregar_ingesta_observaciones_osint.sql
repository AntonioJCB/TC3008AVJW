ALTER TABLE public.resultados_crudos
	ADD COLUMN IF NOT EXISTS hash_contenido text;

UPDATE public.resultados_crudos
SET hash_contenido = md5(contenido::text)
WHERE hash_contenido IS NULL;

ALTER TABLE public.resultados_crudos
	ALTER COLUMN hash_contenido SET NOT NULL;

ALTER TABLE public.resultados_fuentes
	ADD COLUMN IF NOT EXISTS ya_procesado boolean NOT NULL DEFAULT false,
	ADD COLUMN IF NOT EXISTS observaciones_generadas integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS activos_nuevos integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS activos_existentes integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS observaciones_nuevas integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS observaciones_duplicadas integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS descartadas jsonb NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
	IF EXISTS (
		SELECT 1
		FROM public.resultados_crudos
		GROUP BY escaneo_id, fuente_id, hash_contenido
		HAVING count(*) > 1
	) THEN
		RAISE EXCEPTION 'Hay resultados crudos duplicados por escaneo/fuente; consolídalos antes de aplicar la migración';
	END IF;

	IF EXISTS (
		SELECT 1
		FROM public.activos
		GROUP BY organizacion_id, tipo, valor
		HAVING count(*) > 1
	) THEN
		RAISE EXCEPTION 'Hay activos duplicados por organización/tipo/valor; consolídalos antes de aplicar la migración';
	END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS resultados_crudos_dedupe_idx
	ON public.resultados_crudos (escaneo_id, fuente_id, hash_contenido);

CREATE UNIQUE INDEX IF NOT EXISTS activos_organizacion_tipo_valor_idx
	ON public.activos (organizacion_id, tipo, valor);

CREATE TABLE IF NOT EXISTS public.observaciones (
	id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
	escaneo_id          uuid        NOT NULL
						REFERENCES public.escaneos (id) ON DELETE CASCADE,
	activo_id           uuid        NOT NULL
						REFERENCES public.activos (id) ON DELETE CASCADE,
	fuente_id           uuid        NOT NULL
						REFERENCES public.fuentes_osint (id),
	resultado_crudo_id  uuid        NOT NULL
						REFERENCES public.resultados_crudos (id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS observaciones_escaneo_idx
	ON public.observaciones (escaneo_id);
CREATE INDEX IF NOT EXISTS observaciones_activo_idx
	ON public.observaciones (activo_id);
CREATE INDEX IF NOT EXISTS observaciones_fuente_idx
	ON public.observaciones (fuente_id);

ALTER TABLE public.observaciones ENABLE ROW LEVEL SECURITY;

CREATE POLICY observaciones_select ON public.observaciones
	FOR SELECT TO authenticated
	USING (EXISTS (
		SELECT 1
		FROM public.escaneos e
		WHERE e.id = escaneo_id
		  AND e.organizacion_id = (SELECT public.mi_organizacion_id())
	));

REVOKE ALL ON public.observaciones FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.observaciones TO authenticated;
GRANT ALL ON public.observaciones TO service_role;

CREATE OR REPLACE FUNCTION public.ingestar_observaciones(
	p_organizacion_id uuid,
	p_escaneo_id uuid,
	p_fuente_id uuid,
	p_resultado_crudo_id uuid,
	p_items jsonb,
	p_marcar_procesado boolean DEFAULT false
)
RETURNS TABLE (
	activos_nuevos integer,
	activos_existentes integer,
	observaciones_nuevas integer,
	observaciones_duplicadas integer
)
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
	v_item jsonb;
	v_tipo text;
	v_valor text;
	v_atributo text;
	v_datos jsonb;
	v_observado_en timestamptz;
	v_activo_id uuid;
	v_observacion_id uuid;
	v_activos_nuevos integer := 0;
	v_activos_existentes integer := 0;
	v_observaciones_nuevas integer := 0;
	v_observaciones_duplicadas integer := 0;
BEGIN
	IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' THEN
		RAISE EXCEPTION 'p_items debe ser un arreglo JSON';
	END IF;

	IF NOT EXISTS (
		SELECT 1 FROM public.escaneos e
		WHERE e.id = p_escaneo_id AND e.organizacion_id = p_organizacion_id
	) THEN
		RAISE EXCEPTION 'El escaneo no pertenece a la organización';
	END IF;

	IF NOT EXISTS (
		SELECT 1 FROM public.resultados_crudos r
		WHERE r.id = p_resultado_crudo_id
		  AND r.escaneo_id = p_escaneo_id
		  AND r.fuente_id = p_fuente_id
	) THEN
		RAISE EXCEPTION 'El resultado crudo no corresponde al escaneo y fuente';
	END IF;

	FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) AS items(value)
	LOOP
		v_tipo := v_item ->> 'tipo';
		v_valor := v_item ->> 'valor';
		v_atributo := v_item ->> 'atributo';
		v_datos := COALESCE(v_item -> 'datos', '{}'::jsonb);
		v_observado_en := COALESCE((v_item ->> 'observado_en')::timestamptz, now());

		  IF v_tipo IS NULL
			  OR v_tipo NOT IN ('dominio', 'subdominio', 'ip', 'correo', 'servicio')
		   OR v_valor IS NULL OR length(v_valor) = 0
			  OR v_atributo IS NULL
		   OR v_atributo NOT IN (
			   'descubierto', 'certificado', 'servicio_expuesto',
			   'resuelve_a', 'cve', 'info_host'
		   )
		   OR jsonb_typeof(v_datos) <> 'object' THEN
			RAISE EXCEPTION 'Observación normalizada inválida';
		END IF;

		INSERT INTO public.activos (
			organizacion_id, tipo, valor, visto_primera_vez, visto_ultima_vez
		)
		VALUES (p_organizacion_id, v_tipo, v_valor, v_observado_en, v_observado_en)
		ON CONFLICT (organizacion_id, tipo, valor) DO NOTHING
		RETURNING id INTO v_activo_id;

		IF v_activo_id IS NULL THEN
			UPDATE public.activos a
			SET visto_primera_vez = LEAST(a.visto_primera_vez, v_observado_en),
				visto_ultima_vez = GREATEST(a.visto_ultima_vez, v_observado_en)
			WHERE a.organizacion_id = p_organizacion_id
			  AND a.tipo = v_tipo
			  AND a.valor = v_valor
			RETURNING id INTO v_activo_id;
			v_activos_existentes := v_activos_existentes + 1;
		ELSE
			v_activos_nuevos := v_activos_nuevos + 1;
		END IF;

		INSERT INTO public.observaciones (
			escaneo_id, activo_id, fuente_id, resultado_crudo_id,
			atributo, datos, observado_en
		)
		VALUES (
			p_escaneo_id, v_activo_id, p_fuente_id, p_resultado_crudo_id,
			v_atributo, v_datos, v_observado_en
		)
		ON CONFLICT (escaneo_id, activo_id, fuente_id, atributo, datos_hash) DO NOTHING
		RETURNING id INTO v_observacion_id;

		IF v_observacion_id IS NULL THEN
			v_observaciones_duplicadas := v_observaciones_duplicadas + 1;
		ELSE
			v_observaciones_nuevas := v_observaciones_nuevas + 1;
		END IF;
		v_activo_id := NULL;
		v_observacion_id := NULL;
	END LOOP;

	IF p_marcar_procesado THEN
		UPDATE public.resultados_crudos
		SET estado = 'procesado'
		WHERE id = p_resultado_crudo_id
		  AND escaneo_id = p_escaneo_id
		  AND fuente_id = p_fuente_id;
	END IF;

	RETURN QUERY SELECT
		v_activos_nuevos,
		v_activos_existentes,
		v_observaciones_nuevas,
		v_observaciones_duplicadas;
END;
$$;

REVOKE ALL ON FUNCTION public.ingestar_observaciones(
	uuid, uuid, uuid, uuid, jsonb, boolean
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ingestar_observaciones(
	uuid, uuid, uuid, uuid, jsonb, boolean
) TO service_role;
