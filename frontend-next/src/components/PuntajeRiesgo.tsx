import { ETIQUETA_CATEGORIA, ETIQUETA_MOTIVO, nivelDeRiesgo } from "@/lib/formato";
import type { Riesgo } from "@/lib/tipos";

const CATEGORIAS = ["infraestructura", "identidad_digital", "configuracion", "fuga_de_datos"] as const;

export function PuntajeRiesgo({ riesgo }: { riesgo: Riesgo }) {
  const { cobertura } = riesgo;
  const nivel = nivelDeRiesgo(riesgo.puntaje_global);
  return (
    <section className="tarjeta">
      <div className="riesgo-cabecera">
        <div className={`riesgo-numero riesgo-${nivel}`} aria-label={`Puntaje de riesgo global ${riesgo.puntaje_global} de 100`}>
          {riesgo.puntaje_global}
          <small>/100</small>
        </div>
        <div>
          <h2>Riesgo global</h2>
          <p className="suave">0 es sin riesgo detectado; 100 es el máximo.</p>
        </div>
      </div>

      {riesgo.es_parcial && (
        <p className="aviso" role="alert">
          <strong>Puntaje parcial.</strong> No terminó {riesgo.fuentes_faltantes.join(", ")}; el riesgo real puede ser mayor
          al que se muestra.
        </p>
      )}

      <div className="categorias">
        {CATEGORIAS.map((c) => (
          <div key={c} className="categoria">
            <div className="categoria-fila">
              <span>{ETIQUETA_CATEGORIA[c]}</span>
              <strong>{riesgo[c]}</strong>
            </div>
            <div className="barra">
              <div className={`barra-relleno riesgo-${nivelDeRiesgo(riesgo[c])}`} style={{ width: `${riesgo[c]}%` }} />
            </div>
          </div>
        ))}
      </div>

      <details className="cobertura">
        <summary>
          Cobertura: se evaluaron {cobertura.evaluadas.length} de {cobertura.total_reglas} reglas ({cobertura.porcentaje_evaluadas}%)
        </summary>
        <p className="suave">
          Una regla que no se evalúa no significa “sin problemas”: significa que este escaneo no pudo comprobarla.
        </p>
        <ul>
          {cobertura.no_evaluadas.map((n) => (
            <li key={n.codigo}>
              <code>{n.codigo}</code>: {ETIQUETA_MOTIVO[n.motivo]}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}
