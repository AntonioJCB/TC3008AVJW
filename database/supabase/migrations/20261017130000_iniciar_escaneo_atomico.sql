-- Reclama un escaneo y prepara sus fuentes en una sola transacción.
-- Un error al crear las filas de fuentes revierte también el cambio de estado.
CREATE OR REPLACE FUNCTION public.iniciar_escaneo(
    p_escaneo_id uuid,
    p_fuentes uuid[]
)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    v_iniciado_en timestamptz := now();
BEGIN
    IF p_fuentes IS NULL OR cardinality(p_fuentes) = 0 THEN
        RAISE EXCEPTION 'El escaneo requiere al menos una fuente';
    END IF;

    UPDATE public.escaneos e
    SET estado = 'ejecutando', iniciado_en = v_iniciado_en
    WHERE e.id = p_escaneo_id
      AND e.estado = 'pendiente'
      AND EXISTS (
          SELECT 1 FROM public.autorizaciones_dominio a
          WHERE a.id = e.autorizacion_id
            AND a.organizacion_id = e.organizacion_id
            AND a.revocada_en IS NULL
            AND (a.expira_en IS NULL OR a.expira_en > v_iniciado_en)
      );
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    INSERT INTO public.resultados_fuentes
        (escaneo_id, fuente_id, estado, iniciado_en)
    SELECT p_escaneo_id, fuente_id, 'ejecutando', v_iniciado_en
    FROM unnest(p_fuentes) AS ids(fuente_id)
    ON CONFLICT (escaneo_id, fuente_id) DO UPDATE SET
        estado = 'ejecutando',
        iniciado_en = EXCLUDED.iniciado_en,
        finalizado_en = NULL,
        error = NULL;

    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION public.iniciar_escaneo(uuid, uuid[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.iniciar_escaneo(uuid, uuid[]) TO service_role;
