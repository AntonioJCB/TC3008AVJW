"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { BannerEstado } from "@/components/BannerEstado";
import { Cabecera } from "@/components/Cabecera";
import { EstadoFuentes } from "@/components/EstadoFuentes";
import { PuntajeRiesgo } from "@/components/PuntajeRiesgo";
import { TablaHallazgos } from "@/components/TablaHallazgos";
import { useEscaneo } from "@/hooks/useEscaneo";
import { useSesion } from "@/hooks/useSesion";
import { api, textoDeError } from "@/lib/api";
import { fecha } from "@/lib/formato";
import { ESTADOS_FINALES, type Hallazgo } from "@/lib/tipos";

export default function EscaneoPage() {
  const { id } = useParams<{ id: string }>();
  const { listo, correo } = useSesion();
  const { escaneo, error, recargar } = useEscaneo(id);
  const [hallazgos, setHallazgos] = useState<Hallazgo[] | null>(null);
  const [errorHallazgos, setErrorHallazgos] = useState<string | null>(null);
  const [recalculando, setRecalculando] = useState(false);

  // Los hallazgos se piden cuando el escaneo ya terminó y su riesgo ya se calculó.
  const riesgoListo = escaneo?.riesgo?.calculado_en ?? null;
  const terminado = escaneo ? ESTADOS_FINALES.includes(escaneo.estado) : false;
  useEffect(() => {
    if (!terminado) return;
    api.obtenerHallazgos(id).then(setHallazgos).catch((e) => setErrorHallazgos(textoDeError(e)));
  }, [id, terminado, riesgoListo]);

  async function recalcular() {
    setRecalculando(true);
    try {
      await api.recalcularRiesgo(id);
      recargar();
    } catch (e) {
      setErrorHallazgos(textoDeError(e));
    } finally {
      setRecalculando(false);
    }
  }

  if (!listo) return <main className="centrado">Cargando…</main>;

  return (
    <>
      <Cabecera correo={correo} />
      <main className="contenido">
        <p>
          <Link href="/">← Escaneos</Link>
        </p>
        {error && !escaneo && <p className="error" role="alert">{error}</p>}
        {!escaneo && !error && <p className="suave">Cargando escaneo…</p>}

        {escaneo && (
          <>
            <h1>{escaneo.dominio ?? "Escaneo"}</h1>
            <p className="suave">
              Inicio: {fecha(escaneo.iniciado_en)} · Fin: {fecha(escaneo.finalizado_en)}
            </p>
            <BannerEstado escaneo={escaneo} />
            {error && <p className="aviso" role="alert">{error} Reintentando…</p>}

            <h2>Fuentes</h2>
            <EstadoFuentes fuentes={escaneo.fuentes} />

            {terminado && !escaneo.riesgo && <p className="suave">Calculando el riesgo…</p>}
            {escaneo.riesgo && <PuntajeRiesgo riesgo={escaneo.riesgo} />}

            {terminado && (
              <>
                <div className="titulo-fila">
                  <h2>Hallazgos</h2>
                  <button type="button" className="boton-secundario" onClick={recalcular} disabled={recalculando}>
                    {recalculando ? "Recalculando…" : "Recalcular riesgo"}
                  </button>
                </div>
                {errorHallazgos && <p className="error" role="alert">{errorHallazgos}</p>}
                {hallazgos === null && !errorHallazgos && <p className="suave">Cargando hallazgos…</p>}
                {hallazgos && <TablaHallazgos hallazgos={hallazgos} />}
              </>
            )}
          </>
        )}
      </main>
    </>
  );
}
