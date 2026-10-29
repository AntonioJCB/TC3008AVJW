import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { FindingRecord } from '../services/findingsMock'
import { severityLabels } from '../services/findingsMock'

export default function PriorityExplanationDialog({ finding, onClose }: { finding: FindingRecord | null; onClose: () => void }) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  return <div className="finding-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="finding-dialog" role="dialog" aria-modal="true" aria-labelledby="priority-dialog-title">
      <button className="finding-dialog-close" type="button" aria-label="Cerrar explicación" onClick={onClose}><X size={18} /></button>
      <span className="finding-dialog-label">CRITERIOS DE PRIORIDAD</span>
      <h2 id="priority-dialog-title">¿Por qué investigar este hallazgo?</h2>
      {finding ? <>
        <p><strong>{finding.title}</strong> aparece en la cola con prioridad {severityLabels[finding.severity].toLowerCase()}, {finding.confidence}% de confianza y un impacto ilustrativo de +{finding.impact} en el Risk Score.</p>
        <dl className="finding-dialog-facts">
          <div><dt>Regla</dt><dd>{finding.rule}</dd></div>
          <div><dt>Evidencia</dt><dd>{finding.traceEvidence}</dd></div>
          <div><dt>Activo</dt><dd>{finding.asset}</dd></div>
          <div><dt>Fuentes</dt><dd>{finding.sources.join(' · ')}</dd></div>
        </dl>
      </> : <p>Selecciona un hallazgo para revisar sus señales de prioridad.</p>}
      <p className="finding-dialog-note">Explicación de ejemplo basada en los datos locales de la maqueta.</p>
    </section>
  </div>
}
