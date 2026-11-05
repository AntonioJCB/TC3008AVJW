-- Gestión de clientes y reglas. Las operaciones de plataforma usan funciones
-- que verifican el usuario activo; el navegador nunca recibe service_role.
ALTER TABLE public.organizaciones
    ADD COLUMN esta_activa boolean NOT NULL DEFAULT true,
    ADD COLUMN archivada_en timestamptz NULL;

-- Suspender una organización corta sus lecturas y escrituras bajo RLS.
CREATE OR REPLACE FUNCTION public.mi_organizacion_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT u.organizacion_id
    FROM public.usuarios u
    JOIN public.organizaciones o ON o.id = u.organizacion_id
    WHERE u.id = (SELECT auth.uid())
      AND u.esta_activo AND o.esta_activa AND o.archivada_en IS NULL
$$;

-- El resultado nuevo incluye estado y métricas para decidir si un cliente
-- sin datos puede borrarse definitivamente.
CREATE FUNCTION public.listar_clientes_admin()
RETURNS TABLE (
    id uuid, nombre text, dominio_principal text, creado_en timestamptz,
    integrantes bigint, escaneos bigint, activos bigint,
    autorizaciones bigint, esta_activa boolean, archivada_en timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    RETURN QUERY
        SELECT o.id, o.nombre, o.dominio_principal, o.creado_en,
               (SELECT count(*) FROM public.usuarios u WHERE u.organizacion_id = o.id),
               (SELECT count(*) FROM public.escaneos e WHERE e.organizacion_id = o.id),
               (SELECT count(*) FROM public.activos a WHERE a.organizacion_id = o.id),
               (SELECT count(*) FROM public.autorizaciones_dominio ad WHERE ad.organizacion_id = o.id),
               o.esta_activa, o.archivada_en
        FROM public.organizaciones o ORDER BY o.creado_en DESC;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.listar_clientes_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_clientes_admin() TO authenticated;

CREATE FUNCTION public.listar_usuarios_cliente(p_organizacion_id uuid)
RETURNS TABLE (id uuid, nombre text, correo text, rol text, esta_activo boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    RETURN QUERY
        SELECT u.id, u.nombre, u.correo, u.rol, u.esta_activo
        FROM public.usuarios u
        WHERE u.organizacion_id = p_organizacion_id ORDER BY u.nombre;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.listar_usuarios_cliente(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_usuarios_cliente(uuid) TO authenticated;

CREATE FUNCTION public.actualizar_cliente(p_id uuid, p_nombre text, p_dominio text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
    v_nombre text := trim(p_nombre);
    v_dominio text := lower(trim(p_dominio));
    v_anterior public.organizaciones%ROWTYPE;
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    IF v_nombre IS NULL OR length(v_nombre) < 2 OR length(v_nombre) > 120 THEN
        RAISE EXCEPTION 'Nombre de cliente inválido';
    END IF;
    IF v_dominio IS NULL OR length(v_dominio) > 253 OR v_dominio !~
       '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$'
       OR EXISTS (SELECT 1 FROM unnest(string_to_array(v_dominio, '.')) AS label WHERE length(label) > 63) THEN
        RAISE EXCEPTION 'Dominio inválido';
    END IF;
    SELECT * INTO v_anterior FROM public.organizaciones WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR v_anterior.archivada_en IS NOT NULL THEN
        RAISE EXCEPTION 'Cliente inexistente o archivado';
    END IF;
    IF v_dominio <> v_anterior.dominio_principal AND EXISTS (
        SELECT 1 FROM public.escaneos
        WHERE organizacion_id = p_id AND estado IN ('pendiente', 'ejecutando')
    ) THEN RAISE EXCEPTION 'Hay escaneos pendientes o en ejecución'; END IF;

    UPDATE public.organizaciones
    SET nombre = v_nombre, dominio_principal = v_dominio WHERE id = p_id;
    INSERT INTO public.bitacora_auditoria
        (usuario_id, organizacion_id, accion, entidad, entidad_id, detalle)
    VALUES ((SELECT auth.uid()), p_id, 'actualizar', 'organizaciones', p_id,
            jsonb_build_object('nombre_anterior', v_anterior.nombre,
                               'dominio_anterior', v_anterior.dominio_principal));
END;
$$;
REVOKE EXECUTE ON FUNCTION public.actualizar_cliente(uuid, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.actualizar_cliente(uuid, text, text) TO authenticated;

CREATE FUNCTION public.cambiar_estado_cliente(p_id uuid, p_accion text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_cliente public.organizaciones%ROWTYPE;
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    IF p_accion NOT IN ('habilitar', 'deshabilitar', 'archivar', 'restaurar') THEN
        RAISE EXCEPTION 'Acción inválida';
    END IF;
    SELECT * INTO v_cliente FROM public.organizaciones WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Cliente inexistente'; END IF;
    IF p_accion IN ('deshabilitar', 'archivar') AND EXISTS (
        SELECT 1 FROM public.escaneos
        WHERE organizacion_id = p_id AND estado = 'ejecutando'
    ) THEN RAISE EXCEPTION 'Hay un escaneo en ejecución'; END IF;
    IF p_accion IN ('habilitar', 'deshabilitar') AND v_cliente.archivada_en IS NOT NULL THEN
        RAISE EXCEPTION 'Restaura primero el cliente archivado';
    END IF;
    UPDATE public.organizaciones SET
        esta_activa = p_accion IN ('habilitar', 'restaurar'),
        archivada_en = CASE
            WHEN p_accion = 'archivar' THEN now()
            WHEN p_accion = 'restaurar' THEN NULL
            ELSE archivada_en END
    WHERE id = p_id;
    INSERT INTO public.bitacora_auditoria
        (usuario_id, organizacion_id, accion, entidad, entidad_id)
    VALUES ((SELECT auth.uid()), p_id, p_accion, 'organizaciones', p_id);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.cambiar_estado_cliente(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cambiar_estado_cliente(uuid, text) TO authenticated;

-- La eliminación física se limita a clientes sin cuentas ni datos operativos.
-- Los clientes con historial se archivan y pueden restaurarse.
CREATE FUNCTION public.eliminar_cliente_vacio(p_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    PERFORM 1 FROM public.organizaciones WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Cliente inexistente'; END IF;
    IF EXISTS (SELECT 1 FROM public.usuarios WHERE organizacion_id = p_id)
       OR EXISTS (SELECT 1 FROM public.escaneos WHERE organizacion_id = p_id)
       OR EXISTS (SELECT 1 FROM public.activos WHERE organizacion_id = p_id)
       OR EXISTS (SELECT 1 FROM public.autorizaciones_dominio WHERE organizacion_id = p_id) THEN
        RAISE EXCEPTION 'El cliente tiene cuentas o historial; archívalo en su lugar';
    END IF;
    DELETE FROM public.organizaciones WHERE id = p_id;
    INSERT INTO public.bitacora_auditoria (usuario_id, accion, entidad, entidad_id)
    VALUES ((SELECT auth.uid()), 'eliminar', 'organizaciones', p_id);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.eliminar_cliente_vacio(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.eliminar_cliente_vacio(uuid) TO authenticated;

CREATE FUNCTION public.actualizar_usuario_cliente(
    p_usuario_id uuid, p_organizacion_id uuid, p_nombre text,
    p_rol text, p_esta_activo boolean
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_nombre text := trim(p_nombre);
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    IF v_nombre IS NULL OR length(v_nombre) < 2 OR length(v_nombre) > 120
       OR p_rol NOT IN ('admin', 'analista', 'lector') OR p_esta_activo IS NULL THEN
        RAISE EXCEPTION 'Datos de usuario inválidos';
    END IF;
    IF NOT p_esta_activo AND EXISTS (
        SELECT 1 FROM public.administradores_plataforma WHERE usuario_id = p_usuario_id
    ) THEN RAISE EXCEPTION 'No se puede desactivar una cuenta de plataforma'; END IF;
    UPDATE public.usuarios
    SET nombre = v_nombre, rol = p_rol, esta_activo = p_esta_activo
    WHERE id = p_usuario_id AND organizacion_id = p_organizacion_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Usuario no pertenece al cliente'; END IF;
    INSERT INTO public.bitacora_auditoria
        (usuario_id, organizacion_id, accion, entidad, entidad_id, detalle)
    VALUES ((SELECT auth.uid()), p_organizacion_id, 'actualizar', 'usuarios',
            p_usuario_id, jsonb_build_object('rol', p_rol, 'esta_activo', p_esta_activo));
END;
$$;
REVOKE EXECUTE ON FUNCTION public.actualizar_usuario_cliente(uuid, uuid, text, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.actualizar_usuario_cliente(uuid, uuid, text, text, boolean) TO authenticated;

CREATE FUNCTION public.configurar_regla_riesgo(p_id uuid, p_peso integer, p_esta_activa boolean)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN RAISE EXCEPTION 'No autorizado'; END IF;
    IF p_peso IS NULL OR p_peso < 0 OR p_peso > 100 OR p_esta_activa IS NULL THEN
        RAISE EXCEPTION 'Configuración inválida';
    END IF;
    UPDATE public.reglas_riesgo
    SET peso = p_peso, esta_activa = p_esta_activa WHERE id = p_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Regla inexistente'; END IF;
    INSERT INTO public.bitacora_auditoria
        (usuario_id, accion, entidad, entidad_id, detalle)
    VALUES ((SELECT auth.uid()), 'configurar', 'reglas_riesgo', p_id,
            jsonb_build_object('peso', p_peso, 'esta_activa', p_esta_activa));
END;
$$;
REVOKE EXECUTE ON FUNCTION public.configurar_regla_riesgo(uuid, integer, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.configurar_regla_riesgo(uuid, integer, boolean) TO authenticated;
