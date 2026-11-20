-- Marca fuera del riesgo los hallazgos que ya no cumplen una regla.
-- Conserva la fila, su estado y su evidencia para auditoría.
-- CREATE OR REPLACE mantiene el permiso existente de service_role.
CREATE OR REPLACE FUNCTION public.guardar_riesgo(
    p_escaneo_id uuid,
    p_hallazgos  jsonb,
    p_puntaje    jsonb
)
RETURNS TABLE (hallazgos_guardados integer, hallazgos_retirados integer)
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    v_guardados integer := 0;
    v_retirados integer := 0;
BEGIN
    IF jsonb_typeof(p_hallazgos) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'p_hallazgos debe ser un arreglo JSON';
    END IF;
    IF jsonb_typeof(p_puntaje) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'p_puntaje debe ser un objeto JSON';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.escaneos e WHERE e.id = p_escaneo_id) THEN
        RAISE EXCEPTION 'El escaneo % no existe', p_escaneo_id;
    END IF;

    WITH nuevos AS (
        SELECT x.activo_id, x.regla_id, x.fuente_id, x.categoria, x.severidad,
               x.confianza, COALESCE(x.evidencia, '{}'::jsonb) AS evidencia,
               CASE WHEN x.estado IN ('abierto', 'nuevo', 'revisado', 'aceptado')
                    THEN x.estado ELSE 'abierto' END AS estado
        FROM jsonb_to_recordset(p_hallazgos) AS x(
            activo_id uuid, regla_id uuid, fuente_id uuid, categoria text,
            severidad text, confianza numeric, evidencia jsonb, estado text
        )
    ),
    guardados AS (
        INSERT INTO public.hallazgos
            (escaneo_id, activo_id, fuente_id, regla_id, categoria, severidad, confianza, evidencia, estado)
        SELECT p_escaneo_id, n.activo_id, n.fuente_id, n.regla_id, n.categoria,
               n.severidad, n.confianza, n.evidencia, n.estado
        FROM nuevos n
        ON CONFLICT (escaneo_id, activo_id, regla_id) DO UPDATE SET
            fuente_id = EXCLUDED.fuente_id,
            categoria = EXCLUDED.categoria,
            severidad = EXCLUDED.severidad,
            confianza = EXCLUDED.confianza,
            evidencia = EXCLUDED.evidencia
        RETURNING 1
    )
    SELECT count(*)::integer INTO v_guardados FROM guardados;

    UPDATE public.hallazgos h
    SET evidencia = COALESCE(h.evidencia, '{}'::jsonb) || jsonb_build_object(
        'retirado_del_riesgo', true,
        'retirado_del_riesgo_en', now()
    )
    WHERE h.escaneo_id = p_escaneo_id
      AND h.estado IN ('abierto', 'nuevo', 'revisado', 'aceptado')
      AND (h.evidencia ->> 'retirado_del_riesgo') IS DISTINCT FROM 'true'
      AND NOT EXISTS (
          SELECT 1
          FROM jsonb_to_recordset(p_hallazgos) AS x(activo_id uuid, regla_id uuid)
          WHERE x.activo_id = h.activo_id AND x.regla_id IS NOT DISTINCT FROM h.regla_id
      );
    GET DIAGNOSTICS v_retirados = ROW_COUNT;

    INSERT INTO public.puntajes_riesgo (
        escaneo_id, puntaje_global, infraestructura, identidad_digital,
        configuracion, fuga_de_datos, es_parcial, fuentes_faltantes,
        cobertura, version_motor, calculado_en
    )
    VALUES (
        p_escaneo_id,
        (p_puntaje ->> 'puntaje_global')::integer,
        (p_puntaje ->> 'infraestructura')::integer,
        (p_puntaje ->> 'identidad_digital')::integer,
        (p_puntaje ->> 'configuracion')::integer,
        (p_puntaje ->> 'fuga_de_datos')::integer,
        COALESCE((p_puntaje ->> 'es_parcial')::boolean, false),
        COALESCE(
            ARRAY(SELECT jsonb_array_elements_text(p_puntaje -> 'fuentes_faltantes')),
            '{}'::text[]
        ),
        COALESCE(p_puntaje -> 'cobertura', '{}'::jsonb),
        p_puntaje ->> 'version_motor',
        now()
    )
    ON CONFLICT (escaneo_id) DO UPDATE SET
        puntaje_global    = EXCLUDED.puntaje_global,
        infraestructura   = EXCLUDED.infraestructura,
        identidad_digital = EXCLUDED.identidad_digital,
        configuracion     = EXCLUDED.configuracion,
        fuga_de_datos     = EXCLUDED.fuga_de_datos,
        es_parcial        = EXCLUDED.es_parcial,
        fuentes_faltantes = EXCLUDED.fuentes_faltantes,
        cobertura         = EXCLUDED.cobertura,
        version_motor     = EXCLUDED.version_motor,
        calculado_en      = EXCLUDED.calculado_en;

    RETURN QUERY SELECT v_guardados, v_retirados;
END;
$$;

