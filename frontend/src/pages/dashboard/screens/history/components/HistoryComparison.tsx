import { historyScans, historyStats } from '../services/historyMock'

const previousDate = historyScans.at(-2)!.date

export default function HistoryComparison() {
  return <aside className="content-card history-comparison" aria-labelledby="history-comparison-title">
    <span className="history-panel-label">COMPARACIÓN RÁPIDA</span>
    <h2 id="history-comparison-title">Hoy vs. {previousDate}</h2>
    <p>El incremento se concentra en nueva superficie pública y no en cambios de identidad.</p>
    <div className="history-score-comparison">
      <div><span>ANTERIOR</span><strong>{historyStats.previousScore}</strong><small>{previousDate} · 08:14</small></div>
      <i>+{historyStats.scoreDelta}</i>
      <div><span>ACTUAL</span><strong>{historyStats.currentScore}</strong><small>Hoy · 10:32</small></div>
    </div>
    <dl className="history-deltas">
      <div><dt>Activos</dt><dd>+{historyStats.newAssets}</dd></div>
      <div><dt>Hallazgos</dt><dd>+{historyStats.newFindings}</dd></div>
      <div><dt>Críticos</dt><dd>+{historyStats.newCritical}</dd></div>
      <div><dt>Resueltos</dt><dd>{historyStats.resolved}</dd></div>
    </dl>
    <div className="history-dominant-change"><span>CAMBIO DOMINANTE</span><strong>Panel administrativo expuesto</strong><small>+20 puntos brutos antes de controles compensatorios.</small></div>
  </aside>
}
