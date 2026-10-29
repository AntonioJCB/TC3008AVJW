import { sourceStats } from '../services/sourcesMock'

const metrics = [
  { label: 'CONECTADAS', value: sourceStats.connected, detail: 'Fuentes públicas autorizadas', tone: 'default' },
  { label: 'SALUDABLES', value: sourceStats.healthy, detail: 'Respondieron sin incidencias', tone: 'healthy' },
  { label: 'RESPUESTA PARCIAL', value: sourceStats.partial, detail: 'Shodan agotó el tiempo', tone: 'partial' },
  { label: 'COBERTURA', value: `${sourceStats.coverage}%`, detail: `${sourceStats.rawRecords} registros procesados`, tone: 'coverage' },
] as const

export default function SourceKpis() {
  return <div className="source-kpis" aria-label="Resumen de fuentes">
    {metrics.map((metric) => <div className={`content-card source-kpi tone-${metric.tone}`} key={metric.label}>
      <span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small>
    </div>)}
  </div>
}
