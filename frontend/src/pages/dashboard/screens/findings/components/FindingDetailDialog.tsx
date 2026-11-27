import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { FindingRecord } from '../services/findingsMock'
import { evidenceLabels, severityLabels } from '../services/findingsMock'

export default function FindingDetailDialog({ finding, onClose, onResolve, resolving, error }: {
  finding: FindingRecord
  onClose: () => void
  onResolve?: () => void
  resolving?: boolean
  error?: string | null
}) {
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
      {finding.nonConfirmationReason && <p className="finding-dialog-pending">No confirmado: {finding.nonConfirmationReason}</p>}
      {finding.pendingRevalidation && <p className="finding-dialog-pending">Este riesgo sigue abierto, pero la fuente no lo confirmó en el último análisis. Verifica el activo antes de resolverlo.</p>}
      <dl className="finding-dialog-facts">
        <div><dt>Prioridad</dt><dd>{severityLabels[finding.severity]}</dd></div>
        <div><dt>Estado</dt><dd>{finding.status}</dd></div>
        <div><dt>Confianza</dt><dd>{finding.confidence}%</dd></div>
        <div><dt>Nivel de evidencia</dt><dd>{evidenceLabels[finding.evidenceLevel ?? 'sin_clasificar']}</dd></div>
        <div><dt>Contribución</dt><dd>{finding.contributesTo === 'confirmado' && finding.impact !== null ? `Risk Score +${finding.impact}` : finding.contributesTo === 'potencial' && finding.potentialImpact !== null && finding.potentialImpact !== undefined ? `Riesgo potencial +${finding.potentialImpact}` : 'No contribuye'}</dd></div>
        <div><dt>Activo</dt><dd>{finding.asset}</dd></div>
        <div><dt>Regla</dt><dd>{finding.rule}</dd></div>
        <div><dt>Estado de regla</dt><dd>{finding.ruleActive === true ? 'Activa' : finding.ruleActive === false ? 'Inactiva' : 'No disponible'}</dd></div>
        <div><dt>Antigüedad</dt><dd>{finding.ageDays === null || finding.ageDays === undefined ? 'No disponible' : `${finding.ageDays} días`}</dd></div>
        <div><dt>Evidencia</dt><dd>{finding.traceEvidence}</dd></div>
        <div><dt>Fuentes</dt><dd>{finding.sources.join(' · ')}</dd></div>
      </dl>
      {error && <p className="finding-dialog-error" role="alert">{error}</p>}
      {onResolve && finding.status !== 'Resuelto' && <button className="finding-dialog-resolve" type="button" onClick={onResolve} disabled={resolving}>
        {resolving ? 'Actualizando Risk Score…' : 'Marcar como resuelto'}
      </button>}
    </section>
  </div>
}
