import type { FindingRecord } from '../services/findingsMock'
import { evidenceLabels, severityLabels } from '../services/findingsMock'

export default function FindingRow({ finding, selected, onSelect }: { finding: FindingRecord; selected: boolean; onSelect: () => void }) {
  return <button className="finding-record finding-grid" type="button" aria-pressed={selected} onClick={onSelect}>
    <span className="finding-priority"><i className={`finding-severity-dot ${finding.severity}`} aria-hidden="true" /><b>{severityLabels[finding.severity]}</b></span>
    <span className="finding-record-cell"><strong>{finding.title}</strong><small>{finding.asset} <i className={`finding-evidence-level ${finding.evidenceLevel ?? 'sin_clasificar'}`}>{evidenceLabels[finding.evidenceLevel ?? 'sin_clasificar']}</i></small></span>
    <span className="finding-record-cell finding-rule"><strong>{finding.rule}</strong><small>{finding.sources.join(' · ')} · {finding.ruleActive === true ? 'Regla activa' : finding.ruleActive === false ? 'Regla inactiva' : 'Estado de regla no disponible'}{finding.pendingRevalidation ? ' · Pendiente de revalidar' : ''}</small></span>
    <span className="finding-record-cell finding-confidence"><strong>{finding.confidence}%</strong><small>{finding.confidence > 80 ? 'Alta' : 'Media'}</small></span>
    <span><em className={`finding-status ${finding.status === 'Nuevo' ? 'new' : finding.status === 'Resuelto' ? 'resolved' : ''}`}>{finding.status}</em></span>
  </button>
}
