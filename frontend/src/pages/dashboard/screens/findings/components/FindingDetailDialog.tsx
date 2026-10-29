import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { FindingRecord } from '../services/findingsMock'
import { severityLabels } from '../services/findingsMock'

export default function FindingDetailDialog({ finding, onClose }: { finding: FindingRecord; onClose: () => void }) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  return <div className="finding-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="finding-dialog" role="dialog" aria-modal="true" aria-labelledby="finding-dialog-title">
      <button className="finding-dialog-close" type="button" aria-label="Cerrar detalle" onClick={onClose}><X size={18} /></button>
      <span className="finding-dialog-label">DETALLE DEL HALLAZGO</span>
      <h2 id="finding-dialog-title">{finding.title}</h2>
      <p>{finding.description}</p>
      <dl className="finding-dialog-facts">
        <div><dt>Prioridad</dt><dd>{severityLabels[finding.severity]}</dd></div>
        <div><dt>Estado</dt><dd>{finding.status}</dd></div>
        <div><dt>Confianza</dt><dd>{finding.confidence}%</dd></div>
        <div><dt>Impacto de ejemplo</dt><dd>+{finding.impact}</dd></div>
        <div><dt>Activo</dt><dd>{finding.asset}</dd></div>
        <div><dt>Regla</dt><dd>{finding.rule}</dd></div>
        <div><dt>Evidencia</dt><dd>{finding.traceEvidence}</dd></div>
        <div><dt>Fuentes</dt><dd>{finding.sources.join(' · ')}</dd></div>
      </dl>
    </section>
  </div>
}
