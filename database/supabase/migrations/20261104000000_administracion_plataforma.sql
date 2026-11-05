-- La administración de BaxterSec es independiente del rol dentro de cada cliente.
-- Agregar administradores se hace con credenciales de servicio/SQL, nunca desde el navegador.
CREATE TABLE public.administradores_plataforma (
    usuario_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
    creado_en timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.administradores_plataforma ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.administradores_plataforma FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.administradores_plataforma TO authenticated;

CREATE POLICY administradores_plataforma_select_propio
    ON public.administradores_plataforma FOR SELECT TO authenticated
    USING (usuario_id = (SELECT auth.uid()));

CREATE FUNCTION public.es_admin_plataforma()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.administradores_plataforma ap
        JOIN public.usuarios u ON u.id = ap.usuario_id
        WHERE ap.usuario_id = (SELECT auth.uid()) AND u.esta_activo
    )
$$;

REVOKE EXECUTE ON FUNCTION public.es_admin_plataforma() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.es_admin_plataforma() TO authenticated;

-- Lectura global acotada a clientes; el resto de los datos
-- operativos mantiene las políticas de aislamiento por organización.
CREATE POLICY organizaciones_select_plataforma ON public.organizaciones
    FOR SELECT TO authenticated
    USING ((SELECT public.es_admin_plataforma()));

CREATE POLICY organizaciones_update_plataforma ON public.organizaciones
    FOR UPDATE TO authenticated
    USING ((SELECT public.es_admin_plataforma()))
    WITH CHECK ((SELECT public.es_admin_plataforma()));

-- El privilegio de columna existente solo permite UPDATE(nombre).
CREATE FUNCTION public.listar_clientes()
RETURNS TABLE (
    id uuid,
    nombre text,
    dominio_principal text,
    creado_en timestamptz,
    integrantes bigint
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF NOT public.es_admin_plataforma() THEN
        RAISE EXCEPTION 'No autorizado';
    END IF;
    RETURN QUERY
        SELECT o.id, o.nombre, o.dominio_principal, o.creado_en,
               count(u.id) AS integrantes
        FROM public.organizaciones o
        LEFT JOIN public.usuarios u ON u.organizacion_id = o.id AND u.esta_activo
        GROUP BY o.id
        ORDER BY o.creado_en DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.listar_clientes() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_clientes() TO authenticated;

CREATE FUNCTION public.crear_cliente(p_nombre text, p_dominio text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_nombre text := trim(p_nombre);
    v_dominio text := lower(trim(p_dominio));
    v_org uuid;
BEGIN
    IF NOT public.es_admin_plataforma() THEN
        RAISE EXCEPTION 'No autorizado';
    END IF;
    IF length(v_nombre) < 2 OR length(v_nombre) > 120 THEN
        RAISE EXCEPTION 'Nombre de cliente inválido';
    END IF;
    IF length(v_dominio) > 253 OR v_dominio !~
       '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$' THEN
        RAISE EXCEPTION 'Dominio inválido';
    END IF;

    INSERT INTO public.organizaciones (nombre, dominio_principal)
    VALUES (v_nombre, v_dominio)
    RETURNING id INTO v_org;

    INSERT INTO public.bitacora_auditoria (usuario_id, organizacion_id, accion, entidad, entidad_id)
    VALUES ((SELECT auth.uid()), v_org, 'crear', 'organizaciones', v_org);
    RETURN v_org;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.crear_cliente(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.crear_cliente(text, text) TO authenticated;
