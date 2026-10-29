import type { HistoryEvent } from '../services/historyMock'

const icons = { asset: '◇', finding: '△', source: '⌕', scan: '◔' } as const

export default function HistoryRow({ event, onOpen }: { event: HistoryEvent; onOpen: () => void }) {
  return <button className="history-entry history-log-grid" type="button" onClick={onOpen}>
    <time className="history-entry-date"><strong>{event.date}</strong><small>{event.time}</small></time>
    <span className="history-entry-change"><i className={`history-event-icon ${event.kind}${event.status === 'Resuelto' ? ' resolved' : ''}`} aria-hidden="true">{event.status === 'Resuelto' ? '✓' : icons[event.kind]}</i><span><strong>{event.title}</strong><small>{event.detail}</small></span></span>
    <span className="history-entry-cell"><strong>{event.context}</strong><small>{event.contextDetail}</small></span>
    <span className="history-entry-cell"><strong className={`history-impact-${event.impactTone}`}>{event.impact}</strong><small>{event.impactDetail}</small></span>
    <span><em className={`history-status${event.status === 'Nuevo' ? ' new' : ''}${event.status === 'Resuelto' ? ' resolved' : ''}`}>{event.status}</em></span>
  </button>
}
