-- =====================================================================
-- BaxterSec - Integración con Supabase Auth + RLS por organización
-- Pegar en: supabase/migrations/<timestamp>_integrar_auth_y_rls.sql
-- (crear el archivo con: supabase migration new integrar_auth_y_rls)
--
-- Supuestos:
--  * La migración del esquema base ya fue aplicada.
--  * La tabla public.usuarios está vacía (si no, ver nota en el paso 1).
--  * El backend usa la secret key (service_role) para tareas internas:
--    actualizar escaneos, escribir resultados, hallazgos, puntajes y bitácora.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. usuarios pasa a ser tabla de PERFIL ligada a auth.users
--    (Supabase Auth guarda correo y contraseña; aquí ya no hay hash)
--    Nota: si ya hubiera filas en usuarios, la FK fallaría; bórralas antes.
-- ---------------------------------------------------------------------
ALTER TABLE public.usuarios DROP COLUMN IF EXISTS hash_contrasena;
ALTER TABLE public.usuarios ALTER COLUMN id DROP DEFAULT;

-- Un usuario recién registrado aún no pertenece a ninguna organización
ALTER TABLE public.usuarios ALTER COLUMN organizacion_id DROP NOT NULL;

ALTER TABLE public.usuarios ALTER COLUMN rol SET DEFAULT 'lector';
ALTER TABLE public.usuarios
    ADD CONSTRAINT usuarios_rol_check CHECK (rol IN ('admin', 'analista', 'lector'));

ALTER TABLE public.usuarios
    ADD CONSTRAINT usuarios_id_fkey
    FOREIGN KEY (id) REFERENCES auth.users (id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------
-- 2. Trigger: al registrarse alguien en auth.users, crear su perfil
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO public.usuarios (id, nombre, correo)
    VALUES (
        NEW.id,
        COALESCE(NULLIF(NEW.raw_user_meta_data ->> 'nombre', ''), split_part(NEW.email, '@', 1)),
        NEW.email
    );
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ---------------------------------------------------------------------
-- 3. Funciones auxiliares para las políticas
--    SECURITY DEFINER: leen usuarios sin disparar RLS (evita recursión).
--    Un usuario desactivado (esta_activo = false) pierde todo acceso.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.mi_organizacion_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT organizacion_id
    FROM public.usuarios
    WHERE id = (SELECT auth.uid()) AND esta_activo
$$;

CREATE OR REPLACE FUNCTION public.mi_rol()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT rol
    FROM public.usuarios
    WHERE id = (SELECT auth.uid()) AND esta_activo
$$;

-- Regla de negocio clave: solo se escanea con una autorización vigente
-- (de mi organización, no revocada y no expirada)
CREATE OR REPLACE FUNCTION public.autorizacion_vigente(p_autorizacion_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.autorizaciones_dominio a
        WHERE a.id = p_autorizacion_id
          AND a.organizacion_id = public.mi_organizacion_id()
          AND a.revocada_en IS NULL
          AND (a.expira_en IS NULL OR a.expira_en > now())
    )
$$;

REVOKE EXECUTE ON FUNCTION
    public.mi_organizacion_id(), public.mi_rol(), public.autorizacion_vigente(uuid)
    FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION
    public.mi_organizacion_id(), public.mi_rol(), public.autorizacion_vigente(uuid)
    TO authenticated;

-- ---------------------------------------------------------------------
-- 4. Crear una organización (el usuario que la crea queda como admin)
--    Se hace por función porque los clientes no pueden insertar en
--    organizaciones ni cambiar su propio rol directamente.
-- ---------------------------------------------------------------------
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

    IF EXISTS (SELECT 1 FROM public.usuarios WHERE id = v_uid AND organizacion_id IS NOT NULL) THEN
        RAISE EXCEPTION 'El usuario ya pertenece a una organización';
    END IF;

    INSERT INTO public.organizaciones (nombre, dominio_principal)
    VALUES (trim(p_nombre), lower(trim(p_dominio)))
    RETURNING id INTO v_org;

    UPDATE public.usuarios
    SET organizacion_id = v_org, rol = 'admin'
    WHERE id = v_uid;

    INSERT INTO public.bitacora_auditoria (usuario_id, organizacion_id, accion, entidad, entidad_id)
    VALUES (v_uid, v_org, 'crear', 'organizaciones', v_org);

    RETURN v_org;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.crear_organizacion(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.crear_organizacion(text, text) TO authenticated;

-- ---------------------------------------------------------------------
-- 5. Privilegios: defensa en profundidad además de RLS
-- ---------------------------------------------------------------------
-- Los visitantes sin sesión no necesitan tocar ninguna tabla
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- Los usuarios solo pueden modificar columnas concretas, nunca rol,
-- organizacion_id, correo, esta_activo, etc.
REVOKE INSERT, UPDATE, DELETE ON public.usuarios FROM authenticated;
GRANT UPDATE (nombre) ON public.usuarios TO authenticated;

REVOKE UPDATE ON public.organizaciones FROM authenticated;
GRANT UPDATE (nombre) ON public.organizaciones TO authenticated;

-- Una autorización solo puede revocarse (no reescribirse)
REVOKE UPDATE ON public.autorizaciones_dominio FROM authenticated;
GRANT UPDATE (revocada_en) ON public.autorizaciones_dominio TO authenticated;

-- Los analistas solo pueden cambiar el estado de un hallazgo (triage)
REVOKE UPDATE ON public.hallazgos FROM authenticated;
GRANT UPDATE (estado) ON public.hallazgos TO authenticated;

-- ---------------------------------------------------------------------
-- 6. Activar RLS en las 12 tablas
-- ---------------------------------------------------------------------
ALTER TABLE public.organizaciones          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usuarios                ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.autorizaciones_dominio  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fuentes_osint           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activos                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reglas_riesgo           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.escaneos                ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.resultados_crudos       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hallazgos               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.explicaciones_ia        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.puntajes_riesgo         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bitacora_auditoria      ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------
-- 7. Políticas
--    Se envuelven las funciones en (SELECT ...) para que Postgres las
--    evalúe una vez por consulta y no una vez por fila.
-- ---------------------------------------------------------------------

-- organizaciones: ver la propia; el admin puede cambiar su nombre
CREATE POLICY organizaciones_select ON public.organizaciones
    FOR SELECT TO authenticated
    USING (id = (SELECT public.mi_organizacion_id()));

CREATE POLICY organizaciones_update ON public.organizaciones
    FOR UPDATE TO authenticated
    USING (id = (SELECT public.mi_organizacion_id()) AND (SELECT public.mi_rol()) = 'admin')
    WITH CHECK (id = (SELECT public.mi_organizacion_id()));

-- usuarios: ver mi perfil y a mis compañeros; editar solo mi nombre
CREATE POLICY usuarios_select ON public.usuarios
    FOR SELECT TO authenticated
    USING (
        id = (SELECT auth.uid())
        OR organizacion_id = (SELECT public.mi_organizacion_id())
    );

CREATE POLICY usuarios_update_propio ON public.usuarios
    FOR UPDATE TO authenticated
    USING (id = (SELECT auth.uid()))
    WITH CHECK (id = (SELECT auth.uid()));

-- autorizaciones_dominio: el admin las crea y las revoca
CREATE POLICY autorizaciones_select ON public.autorizaciones_dominio
    FOR SELECT TO authenticated
    USING (organizacion_id = (SELECT public.mi_organizacion_id()));

CREATE POLICY autorizaciones_insert ON public.autorizaciones_dominio
    FOR INSERT TO authenticated
    WITH CHECK (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) = 'admin'
        AND autorizado_por = (SELECT auth.uid())
    );

CREATE POLICY autorizaciones_update ON public.autorizaciones_dominio
    FOR UPDATE TO authenticated
    USING (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) = 'admin'
    )
    WITH CHECK (organizacion_id = (SELECT public.mi_organizacion_id()));

-- activos: todos leen; admin y analista escriben; solo admin borra
CREATE POLICY activos_select ON public.activos
    FOR SELECT TO authenticated
    USING (organizacion_id = (SELECT public.mi_organizacion_id()));

CREATE POLICY activos_insert ON public.activos
    FOR INSERT TO authenticated
    WITH CHECK (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) IN ('admin', 'analista')
    );

CREATE POLICY activos_update ON public.activos
    FOR UPDATE TO authenticated
    USING (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) IN ('admin', 'analista')
    )
    WITH CHECK (organizacion_id = (SELECT public.mi_organizacion_id()));

CREATE POLICY activos_delete ON public.activos
    FOR DELETE TO authenticated
    USING (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) = 'admin'
    );

-- escaneos: admin y analista los lanzan, solo con autorización vigente.
-- El backend (service_role) actualiza estado, iniciado_en y finalizado_en.
CREATE POLICY escaneos_select ON public.escaneos
    FOR SELECT TO authenticated
    USING (organizacion_id = (SELECT public.mi_organizacion_id()));

CREATE POLICY escaneos_insert ON public.escaneos
    FOR INSERT TO authenticated
    WITH CHECK (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) IN ('admin', 'analista')
        AND solicitado_por = (SELECT auth.uid())
        AND public.autorizacion_vigente(autorizacion_id)
    );

-- Tablas hijas de escaneos: solo lectura para el cliente.
-- Las escribe el backend con service_role.
CREATE POLICY resultados_crudos_select ON public.resultados_crudos
    FOR SELECT TO authenticated
    USING (escaneo_id IN (
        SELECT id FROM public.escaneos
        WHERE organizacion_id = (SELECT public.mi_organizacion_id())
    ));

CREATE POLICY hallazgos_select ON public.hallazgos
    FOR SELECT TO authenticated
    USING (escaneo_id IN (
        SELECT id FROM public.escaneos
        WHERE organizacion_id = (SELECT public.mi_organizacion_id())
    ));

-- hallazgos: admin y analista pueden cambiar el estado (columna permitida: estado)
CREATE POLICY hallazgos_update ON public.hallazgos
    FOR UPDATE TO authenticated
    USING (
        (SELECT public.mi_rol()) IN ('admin', 'analista')
        AND escaneo_id IN (
            SELECT id FROM public.escaneos
            WHERE organizacion_id = (SELECT public.mi_organizacion_id())
        )
    )
    WITH CHECK (escaneo_id IN (
        SELECT id FROM public.escaneos
        WHERE organizacion_id = (SELECT public.mi_organizacion_id())
    ));

CREATE POLICY explicaciones_ia_select ON public.explicaciones_ia
    FOR SELECT TO authenticated
    USING (escaneo_id IN (
        SELECT id FROM public.escaneos
        WHERE organizacion_id = (SELECT public.mi_organizacion_id())
    ));

CREATE POLICY puntajes_riesgo_select ON public.puntajes_riesgo
    FOR SELECT TO authenticated
    USING (escaneo_id IN (
        SELECT id FROM public.escaneos
        WHERE organizacion_id = (SELECT public.mi_organizacion_id())
    ));

-- bitacora_auditoria: solo el admin la consulta; nadie la modifica desde
-- el cliente (la escribe el backend). No hay políticas de INSERT/UPDATE/DELETE.
CREATE POLICY bitacora_select ON public.bitacora_auditoria
    FOR SELECT TO authenticated
    USING (
        organizacion_id = (SELECT public.mi_organizacion_id())
        AND (SELECT public.mi_rol()) = 'admin'
    );

-- Catálogos globales: cualquier usuario autenticado puede leerlos
CREATE POLICY fuentes_osint_select ON public.fuentes_osint
    FOR SELECT TO authenticated
    USING (true);

CREATE POLICY reglas_riesgo_select ON public.reglas_riesgo
    FOR SELECT TO authenticated
    USING (true);
