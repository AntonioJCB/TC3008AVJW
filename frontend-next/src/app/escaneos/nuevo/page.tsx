"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Cabecera } from "@/components/Cabecera";
import { useSesion } from "@/hooks/useSesion";
import { api, textoDeError } from "@/lib/api";
import { getSupabase } from "@/lib/supabase";
import type { Autorizacion } from "@/lib/tipos";

function vigente(a: Autorizacion): boolean {
  return a.revocada_en === null && (a.expira_en === null || new Date(a.expira_en) > new Date());
}

export default function NuevoEscaneoPage() {
  const router = useRouter();
  const { listo, correo } = useSesion();
  const [autorizaciones, setAutorizaciones] = useState<Autorizacion[] | null>(null);
  const [elegida, setElegida] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [iniciando, setIniciando] = useState(false);

  useEffect(() => {
    if (!listo) return;
    // Row Level Security limita esta consulta a las autorizaciones de tu organización.
    getSupabase()
      .from("autorizaciones_dominio")
      .select("id, alcance, expira_en, revocada_en")
      .order("autorizado_en", { ascending: false })
      .then(({ data, error: err }) => {
        if (err) return setError(err.message);
        const vigentes = ((data ?? []) as Autorizacion[]).filter(vigente);
        setAutorizaciones(vigentes);
        if (vigentes[0]) setElegida(vigentes[0].id);
      });
  }, [listo]);

  async function iniciar() {
    setIniciando(true);
    setError(null);
    try {
      const creado = await api.crearEscaneo(elegida);
      await api.ejecutarEscaneo(creado.escaneo_id); // responde 202: corre en segundo plano
      router.push(`/escaneos/${creado.escaneo_id}`);
    } catch (e) {
      setError(textoDeError(e));
      setIniciando(false);
    }
  }

  if (!listo) return <main className="centrado">Cargando…</main>;

  return (
    <>
      <Cabecera correo={correo} />
      <main className="contenido estrecho">
        <h1>Nuevo escaneo</h1>
        <p className="suave">
          Solo se consulta el dominio principal de tu organización, con fuentes pasivas (crt.sh, Shodan, theHarvester y SpiderFoot).
          Si una falla, las demás continúan y el escaneo queda marcado como incompleto.
        </p>

        {autorizaciones === null && !error && <p className="suave">Cargando autorizaciones…</p>}
        {autorizaciones?.length === 0 && (
          <p className="aviso" role="alert">
            No hay autorizaciones de dominio vigentes. Sin una autorización no se puede escanear.
          </p>
        )}
        {autorizaciones && autorizaciones.length > 0 && (
          <div className="tarjeta formulario">
            <label>
              Autorización
              <select value={elegida} onChange={(e) => setElegida(e.target.value)}>
                {autorizaciones.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.alcance}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" onClick={iniciar} disabled={iniciando || !elegida}>
              {iniciando ? "Iniciando…" : "Iniciar escaneo"}
            </button>
          </div>
        )}
        {error && <p className="error" role="alert">{error}</p>}
      </main>
    </>
  );
}
