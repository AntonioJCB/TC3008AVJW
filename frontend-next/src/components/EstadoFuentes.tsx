import { fecha } from "@/lib/formato";
import type { EstadoFuente, Fuente } from "@/lib/tipos";

const ICONO: Record<EstadoFuente, string> = { pendiente: "○", ejecutando: "◔", completado: "✔", fallido: "✖" };
const TEXTO: Record<EstadoFuente, string> = {
  pendiente: "Pendiente",
  ejecutando: "Consultando…",
  completado: "Terminó bien",
  fallido: "Falló",
};

export function EstadoFuentes({ fuentes }: { fuentes: Fuente[] }) {
  return (
    <ul className="fuentes">
      {fuentes.map((f) => (
        <li key={f.fuente} className={`fuente fuente-${f.estado}`}>
          <span className="fuente-icono" aria-hidden>
            {ICONO[f.estado]}
          </span>
          <div>
            <div className="fuente-nombre">
              {f.fuente} <small>{TEXTO[f.estado]}</small>
            </div>
            {f.estado === "completado" && (
              <small>
                {f.observaciones_nuevas} observaciones nuevas · {f.activos_nuevos} activos nuevos
                {f.finalizado_en ? ` · ${fecha(f.finalizado_en)}` : ""}
              </small>
            )}
            {f.estado === "fallido" && f.error && <small className="fuente-error">{f.error}</small>}
          </div>
        </li>
      ))}
    </ul>
  );
}
