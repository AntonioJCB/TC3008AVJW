-- Nueva identidad de fuente: conservar los IDs de Shodan en evidencia histórica.
-- No modifica reglas, puntajes ni resultados de escaneos anteriores.
INSERT INTO public.fuentes_osint (nombre, tipo_acceso)
VALUES ('Censys', 'api_key')
ON CONFLICT (nombre) DO UPDATE SET tipo_acceso = EXCLUDED.tipo_acceso;
