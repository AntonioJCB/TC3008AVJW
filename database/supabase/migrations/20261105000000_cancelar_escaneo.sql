-- Permite detener un análisis sin confundirlo con una falla del proveedor.
ALTER TABLE public.escaneos DROP CONSTRAINT IF EXISTS escaneos_estado_check;
ALTER TABLE public.escaneos ADD CONSTRAINT escaneos_estado_check
    CHECK (estado IN ('pendiente', 'ejecutando', 'completado', 'incompleto', 'fallido', 'cancelado'))
    NOT VALID;

CREATE OR REPLACE FUNCTION public.cancelar_escaneo(p_escaneo_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    UPDATE public.escaneos
    SET estado = 'cancelado', finalizado_en = now()
    WHERE id = p_escaneo_id AND estado = 'ejecutando';

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    UPDATE public.resultados_fuentes
    SET estado = 'fallido', error = 'Detenido por el usuario', finalizado_en = now()
    WHERE escaneo_id = p_escaneo_id AND estado IN ('pendiente', 'ejecutando');

    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION public.cancelar_escaneo(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cancelar_escaneo(uuid) TO service_role;
