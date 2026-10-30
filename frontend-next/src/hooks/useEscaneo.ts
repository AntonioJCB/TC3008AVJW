"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiError, api, textoDeError } from "@/lib/api";
import { ESTADOS_FINALES, type Escaneo } from "@/lib/tipos";

const CADA_MS = 3000; // consulta mientras el escaneo corre
const ESPERA_RIESGO_MS = 2000; // el riesgo se calcula justo DESPUÉS de cerrar el escaneo
const MAX_ESPERAS_RIESGO = 8;

/** Sigue un escaneo hasta que termina (y hasta que aparece su puntaje de riesgo). */
export function useEscaneo(id: string) {
  const [escaneo, setEscaneo] = useState<Escaneo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const recargar = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => {
    let cancelado = false;
    let temporizador: ReturnType<typeof setTimeout> | undefined;
    let esperasRiesgo = 0;

    async function cargar() {
      try {
        const actual = await api.obtenerEscaneo(id);
        if (cancelado) return;
        setEscaneo(actual);
        setError(null);
        if (!ESTADOS_FINALES.includes(actual.estado)) {
          temporizador = setTimeout(cargar, CADA_MS);
        } else if (!actual.riesgo && esperasRiesgo++ < MAX_ESPERAS_RIESGO) {
          temporizador = setTimeout(cargar, ESPERA_RIESGO_MS);
        }
      } catch (e) {
        if (cancelado) return;
        setError(textoDeError(e));
        // Solo tiene sentido reintentar fallos de red o del servidor (no 401/403/404).
        if (!(e instanceof ApiError) || e.status === 0 || e.status >= 500) {
          temporizador = setTimeout(cargar, CADA_MS * 2);
        }
      }
    }

    void cargar();
    return () => {
      cancelado = true;
      if (temporizador) clearTimeout(temporizador);
    };
  }, [id, version]);

  return { escaneo, error, recargar };
}
