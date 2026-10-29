import { useEffect } from 'react'
import { X } from 'lucide-react'
import { historyScans, historyStats } from '../services/historyMock'

export default function HistoryComparisonDialog({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [onClose])

  return <div className="history-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="history-dialog" role="dialog" aria-modal="true" aria-labelledby="history-compare-title">
      <button className="history-dialog-close" type="button" aria-label="Cerrar comparación" onClick={onClose}><X size={18} /></button>
      <span className="history-dialog-label">COMPARACIÓN DE ANÁLISIS</span>
      <h2 id="history-compare-title">Hoy vs. {historyScans.at(-2)!.date}</h2>
      <p>El Risk Score subió {historyStats.scoreDelta} puntos por señales nuevas en la superficie pública del escenario.</p>
      <dl className="history-dialog-facts">
        <div><dt>Score anterior</dt><dd>{historyStats.previousScore}</dd></div>
        <div><dt>Score actual</dt><dd>{historyStats.currentScore}</dd></div>
        <div><dt>Activos nuevos</dt><dd>+{historyStats.newAssets}</dd></div>
        <div><dt>Hallazgos nuevos</dt><dd>+{historyStats.newFindings}</dd></div>
        <div><dt>Críticos nuevos</dt><dd>+{historyStats.newCritical}</dd></div>
        <div><dt>Resueltos</dt><dd>{historyStats.resolved}</dd></div>
      </dl>
      <p className="history-dialog-note">Comparación ilustrativa con los datos locales de la maqueta.</p>
    </section>
  </div>
}
