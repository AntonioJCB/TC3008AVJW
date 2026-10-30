-- =====================================================================
-- BaxterSec - Preparar una organización y una autorización para probar
-- Ejecutar en: Supabase -> SQL Editor
--
-- Antes: regístrate en la app (o en Authentication -> Users) con tu correo.
-- Cambia las 3 variables de abajo y ejecuta. Al final imprime los ids.
--
-- IMPORTANTE: solo escanees dominios que te pertenezcan o para los que
-- tengas autorización por escrito. La autorización que crea este script es
-- una constancia de que ya cuentas con ese permiso.
-- =====================================================================
DO $$
DECLARE
    v_correo  text := 'tu-correo@ejemplo.com';  -- <- el correo con el que te registraste
    v_dominio text := 'ejemplo.com';            -- <- el dominio que vas a escanear
    v_nombre  text := 'Mi organización';
    v_usuario uuid;
    v_org     uuid;
    v_aut     uuid;
BEGIN
    SELECT u.id, u.organizacion_id INTO v_usuario, v_org
    FROM public.usuarios u
    WHERE lower(u.correo) = lower(v_correo);

    IF v_usuario IS NULL THEN
        RAISE EXCEPTION 'No existe un usuario con el correo %. Regístrate primero.', v_correo;
    END IF;

    IF v_org IS NULL THEN
        INSERT INTO public.organizaciones (nombre, dominio_principal)
        VALUES (v_nombre, lower(btrim(v_dominio)))
        RETURNING id INTO v_org;

        UPDATE public.usuarios SET organizacion_id = v_org, rol = 'admin' WHERE id = v_usuario;
    ELSE
        -- La organización ya existía: se usa su dominio principal
        SELECT dominio_principal INTO v_dominio FROM public.organizaciones WHERE id = v_org;
    END IF;

    -- El alcance debe contener el dominio principal de la organización de forma explícita
    INSERT INTO public.autorizaciones_dominio (organizacion_id, autorizado_por, alcance, referencia_documento)
    VALUES (v_org, v_usuario, lower(btrim(v_dominio)), 'Autorización de prueba')
    RETURNING id INTO v_aut;

    RAISE NOTICE 'usuario_id=%  organizacion_id=%  autorizacion_id=%  dominio=%', v_usuario, v_org, v_aut, v_dominio;
END $$;
