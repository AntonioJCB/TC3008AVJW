import type { SourceRecord } from '../services/sourcesMock'

export default function SourceQuality({ source, onOpenDetail }: { source: SourceRecord | null; onOpenDetail: () => void }) {
  return <section className="content-card source-quality" aria-labelledby="source-quality-heading">
    <span className="source-panel-label" id="source-quality-heading">LECTURA DE CALIDAD</span>
    {source ? <>
      <span className="source-quality-badge">{source.status === 'partial' ? 'COBERTURA PARCIAL' : source.status === 'error' ? 'ERROR DE FUENTE' : 'FUENTE SALUDABLE'}</span>
      <h2>{source.name}</h2>
      <p>{source.description}</p>
      <div className="source-quality-facts">
        <div><span>Cobertura</span><strong className={source.status}>{source.coverage}%</strong></div>
        <div><span>Registros</span><strong>{source.records}</strong></div>
        <div><span>{source.services ? 'Servicios' : 'Respuesta'}</span><strong>{source.services || source.response}</strong></div>
        <div><span>Confianza media</span><strong>{source.confidence}%</strong></div>
      </div>
      <button type="button" className="source-detail-action" onClick={onOpenDetail}>Ver detalle técnico</button>
    </> : <p className="source-quality-empty">Selecciona una fuente del inventario para ver sus detalles.</p>}
  </section>
}
