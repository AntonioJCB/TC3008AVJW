import type { FindingRecord } from '../services/findingsMock'
import { severityLabels } from '../services/findingsMock'

export default function FindingRow({ finding, selected, onSelect }: { finding: FindingRecord; selected: boolean; onSelect: () => void }) {
  return <button className="finding-record finding-grid" type="button" aria-pressed={selected} onClick={onSelect}>
    <span className="finding-priority"><i className={`finding-severity-dot ${finding.severity}`} aria-hidden="true" /><b>{severityLabels[finding.severity]}</b></span>
    <span className="finding-record-cell"><strong>{finding.title}</strong><small>{finding.asset}</small></span>
    <span className="finding-record-cell finding-rule"><strong>{finding.rule}</strong><small>{finding.sources.join(' · ')}</small></span>
    <span className="finding-record-cell finding-confidence"><strong>{finding.confidence}%</strong><small>{finding.confidence > 80 ? 'Alta' : 'Media'}</small></span>
    <span><em className={`finding-status ${finding.status === 'Nuevo' ? 'new' : ''}`}>{finding.status}</em></span>
  </button>
}
