-- El alta en Auth crea un perfil sin cliente. Solo el administrador de
-- plataforma puede enlazarlo a una organización existente.
CREATE FUNCTION public.listar_usuarios_sin_cliente()
RETURNS TABLE (id uuid, nombre text, correo text, creado_en timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN
        RAISE EXCEPTION 'No autorizado';
    END IF;
    RETURN QUERY
        SELECT u.id, u.nombre, u.correo, u.creado_en
        FROM public.usuarios u
        WHERE u.organizacion_id IS NULL AND u.esta_activo
        ORDER BY u.creado_en;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.listar_usuarios_sin_cliente() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_usuarios_sin_cliente() TO authenticated;

CREATE FUNCTION public.asignar_usuario_cliente(
    p_usuario_id uuid,
    p_organizacion_id uuid,
    p_rol text DEFAULT 'lector'
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN
        RAISE EXCEPTION 'No autorizado';
    END IF;
    IF p_rol NOT IN ('admin', 'analista', 'lector') THEN
        RAISE EXCEPTION 'Rol inválido';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.organizaciones WHERE id = p_organizacion_id) THEN
        RAISE EXCEPTION 'Cliente inexistente';
    END IF;

    UPDATE public.usuarios
    SET organizacion_id = p_organizacion_id, rol = p_rol
    WHERE id = p_usuario_id AND organizacion_id IS NULL AND esta_activo;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Usuario inexistente, inactivo o ya asignado';
    END IF;

    INSERT INTO public.bitacora_auditoria
        (usuario_id, organizacion_id, accion, entidad, entidad_id, detalle)
    VALUES ((SELECT auth.uid()), p_organizacion_id, 'asignar', 'usuarios',
            p_usuario_id, jsonb_build_object('rol', p_rol));
END;
$$;

REVOKE EXECUTE ON FUNCTION public.asignar_usuario_cliente(uuid, uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.asignar_usuario_cliente(uuid, uuid, text) TO authenticated;
