"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Cabecera } from "@/components/Cabecera";
import { useSesion } from "@/hooks/useSesion";
import { api, textoDeError } from "@/lib/api";
import { fecha, nivelDeRiesgo } from "@/lib/formato";
import type { EscaneoResumen } from "@/lib/tipos";

export default function InicioPage() {
  const { listo, correo } = useSesion();
  const [escaneos, setEscaneos] = useState<EscaneoResumen[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!listo) return;
    api.listarEscaneos().then(setEscaneos).catch((e) => setError(textoDeError(e)));
  }, [listo]);

  if (!listo) return <main className="centrado">Cargando…</main>;

  return (
    <>
      <Cabecera correo={correo} />
      <main className="contenido">
        <div className="titulo-fila">
          <h1>Escaneos</h1>
          <Link href="/escaneos/nuevo" className="boton">
            Nuevo escaneo
          </Link>
        </div>
        {error && <p className="error" role="alert">{error}</p>}
        {escaneos === null && !error && <p className="suave">Cargando…</p>}
        {escaneos?.length === 0 && <p className="suave">Aún no hay escaneos. Inicia el primero.</p>}
        {escaneos && escaneos.length > 0 && (
          <table className="tabla">
            <thead>
              <tr>
                <th>Dominio</th>
                <th>Estado</th>
                <th>Riesgo</th>
                <th>Inicio</th>
              </tr>
            </thead>
            <tbody>
              {escaneos.map((e) => (
                <tr key={e.escaneo_id}>
                  <td>
                    <Link href={`/escaneos/${e.escaneo_id}`}>{e.dominio}</Link>
                  </td>
                  <td>
                    <span className={`etiqueta etiqueta-${e.estado}`}>{e.estado}</span>
                  </td>
                  <td>
                    {e.puntaje_global === null ? (
                      "—"
                    ) : (
                      <span className={`riesgo-texto riesgo-${nivelDeRiesgo(e.puntaje_global)}`}>
                        {e.puntaje_global}
                        {e.es_parcial ? " (parcial)" : ""}
                      </span>
                    )}
                  </td>
                  <td>{fecha(e.iniciado_en)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </>
  );
}
