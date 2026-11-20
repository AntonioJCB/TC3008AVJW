-- Web realizaba solicitudes directas a los hosts. Se conserva su catálogo y
-- evidencia histórica, pero sus reglas dejan de ser puntuables en OSINT pasivo.
-- CONF-001/002 también dependían de la comprobación TLS activa de Web.
UPDATE public.reglas_riesgo
SET esta_activa = false
WHERE codigo IN ('CONF-001', 'CONF-002', 'CONF-006', 'CONF-007', 'CONF-008')
  AND esta_activa = true;
