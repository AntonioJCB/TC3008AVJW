-- Calibración conservadora: señales sin verificación activa se conservan como
-- hallazgos informativos, pero no elevan el Risk Score.

UPDATE public.reglas_riesgo
SET peso = 15
WHERE codigo = 'INFRA-001' AND peso = 20;

UPDATE public.reglas_riesgo
SET nombre = 'CVE reportada por una fuente OSINT',
    descripcion = 'Posible vulnerabilidad asociada a un activo; requiere verificación técnica.',
    peso = CASE WHEN peso = 10 THEN 8 ELSE peso END
WHERE codigo = 'INFRA-003';

UPDATE public.reglas_riesgo
SET nombre = 'Certificado histórico de CT expirado',
    descripcion = 'Requiere verificar el certificado que sirve actualmente el dominio.',
    severidad = 'baja',
    peso = 0
WHERE codigo = 'CONF-001';

UPDATE public.reglas_riesgo
SET nombre = 'Certificado histórico de CT próximo a expirar',
    descripcion = 'Requiere verificar el certificado que sirve actualmente el dominio.',
    severidad = 'baja',
    peso = 0
WHERE codigo = 'CONF-002';

UPDATE public.reglas_riesgo
SET nombre = 'Correo corporativo encontrado en fuente pública',
    descripcion = 'La publicación de una dirección no demuestra filtración de credenciales.',
    peso = 0
WHERE codigo = 'IDEN-003';

-- Las reglas sin evaluador siguen en el catálogo para desarrollo, pero ya no
-- aparecen activas en la configuración de este proyecto.
UPDATE public.reglas_riesgo
SET esta_activa = false
WHERE codigo IN (
    'INFRA-004', 'CONF-003', 'CONF-004', 'CONF-005',
    'IDEN-001', 'IDEN-002',
    'FUGA-001', 'FUGA-002', 'FUGA-003', 'FUGA-004'
);
