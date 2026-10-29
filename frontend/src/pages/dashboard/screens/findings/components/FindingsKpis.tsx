import { findingStats } from '../services/findingsMock'

const kpis = [
  { label: 'TOTAL', value: findingStats.total, detail: `+${findingStats.new} desde el análisis anterior`, tone: 'total' },
  { label: 'CRÍTICOS', value: findingStats.critical, detail: 'Requieren revisión inmediata', tone: 'critical' },
  { label: 'ALTA CONFIANZA', value: findingStats.highConfidence, detail: 'Confianza superior al 80%', tone: 'confidence' },
  { label: 'NUEVOS', value: findingStats.new, detail: 'Detectados en este análisis', tone: 'new' },
]

export default function FindingsKpis() {
  return <div className="finding-kpis" aria-label="Resumen de hallazgos">
    {kpis.map((kpi) => <article className={`content-card finding-kpi tone-${kpi.tone}`} key={kpi.label}>
      <span>{kpi.label}</span><strong>{kpi.value}</strong><small>{kpi.detail}</small>
    </article>)}
  </div>
}
