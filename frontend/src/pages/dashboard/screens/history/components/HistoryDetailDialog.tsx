import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { HistoryEvent } from '../services/historyMock'

export default function HistoryDetailDialog({ event, onClose }: { event: HistoryEvent; onClose: () => void }) {
  useEffect(() => {
    const closeOnEscape = (keyEvent: KeyboardEvent) => { if (keyEvent.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  return <div className="history-dialog-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) onClose() }}>
    <section className="history-dialog" role="dialog" aria-modal="true" aria-labelledby="history-detail-title">
      <button className="history-dialog-close" type="button" aria-label="Cerrar detalle" onClick={onClose}><X size={18} /></button>
      <span className="history-dialog-label">CAMBIO DEL HISTORIAL</span>
      <h2 id="history-detail-title">{event.title}</h2>
      <p>{event.detail}</p>
      <dl className="history-dialog-facts">
        <div><dt>Fecha</dt><dd>{event.date} · {event.time}</dd></div>
        <div><dt>Estado</dt><dd>{event.status}</dd></div>
        <div><dt>Contexto</dt><dd>{event.context}</dd></div>
        <div><dt>Evidencia</dt><dd>{event.contextDetail}</dd></div>
        <div><dt>Impacto</dt><dd>{event.impact} · {event.impactDetail}</dd></div>
        <div><dt>Seguimiento</dt><dd>{event.followUp ? 'Requiere seguimiento' : 'Sin seguimiento pendiente'}</dd></div>
      </dl>
    </section>
  </div>
}
