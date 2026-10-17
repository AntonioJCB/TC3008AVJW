CREATE TABLE IF NOT EXISTS public.resultados_fuentes (
	id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
	escaneo_id           uuid        NOT NULL
						 REFERENCES public.escaneos (id) ON DELETE CASCADE,
	fuente_id            uuid        NOT NULL
						 REFERENCES public.fuentes_osint (id),
	estado               text        NOT NULL DEFAULT 'pendiente'
						 CHECK (estado IN ('pendiente', 'ejecutando', 'completado', 'fallido')),
	iniciado_en          timestamptz NULL,
	finalizado_en        timestamptz NULL,
	error                text        NULL,
	resultado_crudo_id   uuid        NULL
						 REFERENCES public.resultados_crudos (id) ON DELETE SET NULL,
	UNIQUE (escaneo_id, fuente_id)
);

ALTER TABLE public.resultados_fuentes ENABLE ROW LEVEL SECURITY;

CREATE POLICY resultados_fuentes_select ON public.resultados_fuentes
	FOR SELECT TO authenticated
	USING (EXISTS (
		SELECT 1
		FROM public.escaneos e
		WHERE e.id = escaneo_id
		  AND e.organizacion_id = (SELECT public.mi_organizacion_id())
	));

REVOKE ALL ON public.resultados_fuentes FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.resultados_fuentes TO authenticated;
GRANT ALL ON public.resultados_fuentes TO service_role;
