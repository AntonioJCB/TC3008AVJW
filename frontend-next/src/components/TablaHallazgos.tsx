import { ETIQUETA_CATEGORIA, ETIQUETA_SEVERIDAD } from "@/lib/formato";
import type { Hallazgo } from "@/lib/tipos";

export function TablaHallazgos({ hallazgos }: { hallazgos: Hallazgo[] }) {
  if (hallazgos.length === 0) {
    return <p className="suave">No se encontraron hallazgos con las reglas evaluadas.</p>;
  }
  return (
    <div className="tabla-scroll">
      <table className="tabla">
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Hallazgo</th>
            <th>Activo</th>
            <th>Categoría</th>
            <th>Confianza</th>
            <th>Fuentes</th>
            <th>Estado</th>
          </tr>
        </thead>
        <tbody>
          {hallazgos.map((h) => (
            <tr key={h.id}>
              <td>
                <span className={`sev sev-${h.severidad}`}>{ETIQUETA_SEVERIDAD[h.severidad]}</span>
              </td>
              <td>
                <strong>{h.regla_nombre ?? h.regla_codigo}</strong>
                <br />
                <small className="suave">{h.regla_codigo}</small>
              </td>
              <td>
                <code>{h.activo_valor}</code>
              </td>
              <td>{ETIQUETA_CATEGORIA[h.categoria] ?? h.categoria}</td>
              <td title="Sube cuando más de una fuente independiente coincide">{Math.round(h.confianza * 100)}%</td>
              <td>{h.fuentes.join(", ")}</td>
              <td>{h.estado}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
