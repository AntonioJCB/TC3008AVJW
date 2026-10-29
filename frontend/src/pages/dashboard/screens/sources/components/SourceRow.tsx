import type { SourceRecord } from '../services/sourcesMock'
import SourceStatusIndicator from './SourceStatusIndicator'

export default function SourceRow({ source, selected, onSelect }: { source: SourceRecord; selected: boolean; onSelect: () => void }) {
  return <button type="button" className={`source-record${selected ? ' selected' : ''}`} aria-pressed={selected} onClick={onSelect}>
    <span className="source-identity"><span className={`source-monogram ${source.status}`}>{source.monogram}</span><span><strong>{source.name}</strong><small>{source.type}</small></span></span>
    <span className="source-record-cell"><strong>{source.records} registros</strong><small>{source.contribution}</small></span>
    <span className="source-record-cell"><strong>{source.response}</strong><small>{source.lastConsulted}</small></span>
    <SourceStatusIndicator status={source.status} />
  </button>
}
