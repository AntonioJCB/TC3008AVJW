-- Un solo guardado transaccional para la configuración de reglas.
CREATE FUNCTION public.configurar_reglas_riesgo_lote(p_cambios jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
    v_cambio jsonb;
    v_id uuid;
    v_peso integer;
    v_activa boolean;
    v_ids uuid[] := ARRAY[]::uuid[];
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    IF p_cambios IS NULL OR jsonb_typeof(p_cambios) <> 'array'
       OR jsonb_array_length(p_cambios) > 100 THEN
        RAISE EXCEPTION 'Lista de reglas inválida';
    END IF;
    FOR v_cambio IN SELECT value FROM jsonb_array_elements(p_cambios) LOOP
        IF jsonb_typeof(v_cambio) <> 'object'
           OR jsonb_typeof(v_cambio->'id') <> 'string'
           OR jsonb_typeof(v_cambio->'peso') <> 'number'
           OR jsonb_typeof(v_cambio->'esta_activa') <> 'boolean' THEN
            RAISE EXCEPTION 'Configuración inválida';
        END IF;
        v_id := (v_cambio->>'id')::uuid;
        v_peso := (v_cambio->>'peso')::integer;
        v_activa := (v_cambio->>'esta_activa')::boolean;
        IF v_peso < 0 OR v_peso > 100 OR v_id = ANY(v_ids) THEN
            RAISE EXCEPTION 'Configuración inválida o regla duplicada';
        END IF;
        v_ids := array_append(v_ids, v_id);
        PERFORM 1 FROM public.reglas_riesgo WHERE id = v_id;
        IF NOT FOUND THEN RAISE EXCEPTION 'Regla inexistente'; END IF;
    END LOOP;
    FOR v_cambio IN SELECT value FROM jsonb_array_elements(p_cambios) LOOP
        v_id := (v_cambio->>'id')::uuid;
        v_peso := (v_cambio->>'peso')::integer;
        v_activa := (v_cambio->>'esta_activa')::boolean;
        UPDATE public.reglas_riesgo
        SET peso = v_peso, esta_activa = v_activa WHERE id = v_id;
        INSERT INTO public.bitacora_auditoria
            (usuario_id, accion, entidad, entidad_id, detalle)
        VALUES ((SELECT auth.uid()), 'configurar', 'reglas_riesgo', v_id,
                jsonb_build_object('peso', v_peso, 'esta_activa', v_activa));
    END LOOP;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.configurar_reglas_riesgo_lote(jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.configurar_reglas_riesgo_lote(jsonb) TO authenticated;
