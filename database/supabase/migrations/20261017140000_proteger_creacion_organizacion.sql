-- Conserva la función de alta existente y bloquea cuentas desactivadas.
CREATE OR REPLACE FUNCTION public.crear_organizacion(p_nombre text, p_dominio text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_uid uuid := (SELECT auth.uid());
    v_org uuid;
BEGIN
    IF v_uid IS NULL THEN
        RAISE EXCEPTION 'No autenticado';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.usuarios WHERE id = v_uid AND esta_activo) THEN
        RAISE EXCEPTION 'Usuario inactivo o sin perfil';
    END IF;
    IF NULLIF(btrim(p_nombre), '') IS NULL OR NULLIF(btrim(p_dominio), '') IS NULL THEN
        RAISE EXCEPTION 'Nombre y dominio son obligatorios';
    END IF;
    IF EXISTS (SELECT 1 FROM public.usuarios WHERE id = v_uid AND organizacion_id IS NOT NULL) THEN
        RAISE EXCEPTION 'El usuario ya pertenece a una organización';
    END IF;

    INSERT INTO public.organizaciones (nombre, dominio_principal)
    VALUES (btrim(p_nombre), lower(btrim(p_dominio)))
    RETURNING id INTO v_org;

    UPDATE public.usuarios
    SET organizacion_id = v_org, rol = 'admin'
    WHERE id = v_uid;

    INSERT INTO public.bitacora_auditoria (usuario_id, organizacion_id, accion, entidad, entidad_id)
    VALUES (v_uid, v_org, 'crear', 'organizaciones', v_org);

    RETURN v_org;
END;
$$;
