import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { SourceRecord } from '../services/sourcesMock'

export default function SourceDetailDialog({ source, onClose }: { source: SourceRecord; onClose: () => void }) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  return <div className="source-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="source-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="source-dialog-heading">
      <button type="button" className="source-dialog-close" aria-label="Cerrar detalle" onClick={onClose}><X size={18} /></button>
      <span className="source-panel-label">DETALLE TÉCNICO</span>
      <h2 id="source-dialog-heading">{source.name}</h2>
      <p>{source.description}</p>
      <dl>
        <div><dt>Tipo de dato</dt><dd>{source.type}</dd></div>
        <div><dt>Propósito</dt><dd>{source.purpose}</dd></div>
        <div><dt>Estado</dt><dd>{source.status === 'healthy' ? 'Saludable' : source.status === 'partial' ? 'Parcial' : 'Error'}</dd></div>
        <div><dt>Cobertura</dt><dd>{source.coverage}%</dd></div>
        <div><dt>Registros</dt><dd>{source.records}</dd></div>
        <div><dt>Respuesta</dt><dd>{source.response}</dd></div>
      </dl>
    </section>
  </div>
}
