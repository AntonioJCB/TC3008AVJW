import type { FindingRecord } from '../services/findingsMock'
import { severityLabels } from '../services/findingsMock'

interface Props {
  finding: FindingRecord | null
  priority: number
  onOpenDetail: () => void
}

export default function FindingInsights({ finding, priority, onOpenDetail }: Props) {
  if (!finding) return <aside className="content-card finding-insights finding-insights-empty"><span>HALLAZGO SELECCIONADO</span><p>No hay un hallazgo visible con los filtros actuales.</p></aside>

  return <aside className="content-card finding-insights" aria-label="Hallazgo seleccionado">
    <span className="finding-insights-label">PRIORIDAD {String(priority).padStart(2, '0')}</span>
    <span className={`finding-insights-severity ${finding.severity}`}><i className={`finding-severity-dot ${finding.severity}`} aria-hidden="true" />{severityLabels[finding.severity].toUpperCase()}</span>
    <h2>{finding.title}</h2>
    <p className="finding-insights-description">{finding.description}</p>
    <div className="finding-impact"><span>Impacto en Risk Score</span><strong>+{finding.impact}</strong></div>
    <dl className="finding-trace" aria-label="Ruta de trazabilidad">
      <div><dt>Hallazgo</dt><dd>{finding.traceFinding}</dd></div>
      <div><dt>Evidencia</dt><dd>{finding.traceEvidence}</dd></div>
      <div><dt>Activo</dt><dd>{finding.asset}</dd></div>
      <div><dt>Fuentes</dt><dd>{finding.sources.join(' · ')}</dd></div>
    </dl>
    <button className="finding-open-detail" type="button" onClick={onOpenDetail}>Abrir detalle</button>
    <p className="finding-method-note">✦ La severidad y el score de esta muestra siguen reglas ilustrativas.</p>
  </aside>
}
