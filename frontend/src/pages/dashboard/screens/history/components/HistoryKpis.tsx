import { historyStats } from '../services/historyMock'

const kpis = [
  { label: 'RISK SCORE ACTUAL', value: historyStats.currentScore, detail: `+${historyStats.scoreDelta} desde el análisis anterior`, tone: 'risk' },
  { label: 'ANÁLISIS COMPLETADOS', value: historyStats.completedScans, detail: '30 días de observación', tone: 'scans' },
  { label: 'ACTIVOS NUEVOS', value: `+${historyStats.newAssets}`, detail: 'Desde el 24 de septiembre', tone: 'assets' },
  { label: 'CAMBIOS RELEVANTES', value: historyStats.relevantChanges, detail: `${historyStats.followUpChanges} requieren seguimiento`, tone: 'changes' },
]

export default function HistoryKpis() {
  return <div className="history-kpis" aria-label="Resumen histórico">
    {kpis.map((kpi) => <article className={`content-card history-kpi tone-${kpi.tone}`} key={kpi.label}>
      <span>{kpi.label}</span><strong>{kpi.value}</strong><small>{kpi.detail}</small>
    </article>)}
  </div>
}
