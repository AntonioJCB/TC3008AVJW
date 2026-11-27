-- Activa las banderas del catálogo sin recalcular ni alterar resultados históricos.
-- Las reglas sin evaluador y las retiradas siguen sin puntuar por decisión del motor.
UPDATE public.reglas_riesgo
SET esta_activa = true
WHERE esta_activa = false;
