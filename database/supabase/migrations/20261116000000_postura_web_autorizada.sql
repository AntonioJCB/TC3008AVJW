-- Comprobaciones ligeras por hostname autorizado. No habilita escaneo de IPs.
INSERT INTO public.fuentes_osint (nombre, tipo_acceso)
VALUES ('Web', 'comprobacion_web')
ON CONFLICT (nombre) DO NOTHING;

INSERT INTO public.reglas_riesgo
    (codigo, nombre, descripcion, tipo_activo, categoria, severidad, peso, esta_activa)
VALUES
    ('CONF-006', 'Certificado TLS actual no verificable',
     'La conexión TLS al nombre autorizado falló la validación del certificado.',
     'dominio', 'configuracion', 'media', 12, true),
    ('CONF-007', 'Certificado TLS actual próximo a vencer',
     'El certificado servido por el nombre autorizado vence en 14 días o menos.',
     'dominio', 'configuracion', 'baja', 4, true),
    ('CONF-008', 'Sitio HTTP sin redirección a HTTPS',
     'La raíz del nombre autorizado responde por HTTP sin redirigir a HTTPS.',
     'dominio', 'configuracion', 'media', 6, true)
ON CONFLICT (codigo) DO NOTHING;
