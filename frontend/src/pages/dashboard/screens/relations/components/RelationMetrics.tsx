import { priorityRoutes, relationStats } from '../services/relationsMock'

const metrics = [
  { label: 'CONEXIONES', value: relationStats.connections, tone: 'default' },
  { label: 'RUTAS CRÍTICAS', value: priorityRoutes.length, tone: 'critical' },
  { label: 'ACTIVOS AISLADOS', value: relationStats.isolatedAssets, tone: 'default' },
  { label: 'MAYOR CONCENTRACIÓN', value: relationStats.concentration, tone: 'concentration' },
] as const

export default function RelationMetrics() {
  return <div className="relation-metrics" aria-label="Resumen de relaciones">
    {metrics.map((metric) => <div className={`content-card relation-metric tone-${metric.tone}`} key={metric.label}>
      <span>{metric.label}</span><strong>{metric.value}</strong>
    </div>)}
  </div>
}
