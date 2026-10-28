import { Link } from 'react-router'
import { inventorySummary, overviewSnapshot, priorityFindings, recentMilestones, severitySummary, sourceHealth } from '../services/overviewMock'

export function SummaryCard() {
  return (
    <section className="content-card proposal-card analysis-summary" aria-labelledby="summary-title">
      <div className="card-heading">
        <div><h3 id="summary-title">RESUMEN DEL ANÁLISIS</h3><small>Resultados simulados del último recorrido OSINT.</small></div>
        <span className="card-state">Completado</span>
      </div>
      <div className="summary-numbers">
        <div><strong>{overviewSnapshot.assetCount}</strong><span>Activos</span></div>
        <div><strong>{overviewSnapshot.findingCount}</strong><span>Hallazgos</span></div>
        <div><strong>{overviewSnapshot.criticalCount}</strong><span>Críticos</span></div>
        <div><strong>+{overviewSnapshot.newAssetCount}</strong><span>Activos nuevos</span></div>
      </div>
      <div className="summary-highlights" aria-label="Indicadores de actividad">
        <div><strong>+2</strong><span>Hallazgos nuevos</span></div>
        <div><strong>{overviewSnapshot.processedRecords}</strong><span>Registros procesados</span></div>
        <div><strong>{sourceHealth.length}</strong><span>Fuentes consultadas</span></div>
      </div>
    </section>
  )
}

export function SeverityCard() {
  const max = Math.max(...severitySummary.map(({ count }) => count), 1)
  return (
    <section className="content-card proposal-card severity-card" aria-labelledby="severity-title">
      <div className="card-heading"><h3 id="severity-title">HALLAZGOS POR SEVERIDAD</h3><Link to="/home/hallazgos">Ver todos</Link></div>
      <div className="severity-bars">
        {severitySummary.map(({ label, count, tone }) => (
          <div className="severity-bar-row" key={label}>
            <span>{label}</span>
            <div className="bar-track"><i className={`tone-${tone}`} style={{ width: `${(count / max) * 100}%` }} /></div>
            <strong>{count}</strong>
          </div>
        ))}
      </div>
    </section>
  )
}

export function PriorityFindings() {
  return (
    <section className="content-card proposal-card priorities-card" aria-labelledby="priorities-title">
      <div className="card-heading"><h3 id="priorities-title">HALLAZGOS PRIORITARIOS</h3><Link to="/home/hallazgos">Ver todos los hallazgos</Link></div>
      <div className="priority-table-wrap">
        <table className="priority-table">
          <thead><tr><th>SEVERIDAD</th><th>HALLAZGO</th><th>ACTIVO</th><th title="Valor ilustrativo">CONFIANZA</th><th aria-label="Acción" /></tr></thead>
          <tbody>
            {priorityFindings.map((finding) => (
              <tr key={finding.id}>
                <td><span className={`priority-severity ${finding.severity === 'Crítico' ? 'critical' : 'high'}`}>{finding.severity}</span></td>
                <td><strong>{finding.title}</strong></td>
                <td>{finding.asset}</td>
                <td>{finding.confidence}%</td>
                <td><Link to="/home/hallazgos">Ver</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export function InventoryCard() {
  const max = Math.max(...inventorySummary.map(({ count }) => count), 1)
  return (
    <section className="content-card proposal-card inventory-card" aria-labelledby="inventory-title">
      <div className="card-heading"><h3 id="inventory-title">INVENTARIO DE ACTIVOS</h3><Link to="/home/activos">Explorar activos</Link></div>
      <div className="inventory-bars">
        {inventorySummary.map(({ label, count, tone }) => (
          <div className="inventory-bar-row" key={label}>
            <span>{label}</span><strong>{count}</strong>
            <div className="bar-track"><i className={`tone-${tone}`} style={{ width: `${(count / max) * 100}%` }} /></div>
          </div>
        ))}
      </div>
    </section>
  )
}

export function SourcesCard() {
  return (
    <section className="content-card proposal-card sources-card" aria-labelledby="sources-title">
      <div className="card-heading"><h3 id="sources-title">SALUD DE FUENTES</h3><Link to="/home/fuentes">Detalles</Link></div>
      <div className="source-health-list">
        {sourceHealth.map((source) => <div className={`source-health-row ${source.tone}`} key={source.name}><span className="source-status-dot" /><strong>{source.name}</strong><em>{source.status}</em></div>)}
      </div>
      <div className="sources-foot"><span>Cobertura del análisis</span><strong>{overviewSnapshot.sourceCoverage}%</strong></div>
      <div className="source-progress" role="img" aria-label={`Cobertura ilustrativa: ${overviewSnapshot.sourceCoverage}%`}><i style={{ width: `${overviewSnapshot.sourceCoverage}%` }} /></div>
    </section>
  )
}

export function RecentChanges() {
  return (
    <section className="content-card proposal-card changes-card" aria-labelledby="changes-title">
      <div className="card-heading"><h3 id="changes-title">CAMBIOS RECIENTES</h3><Link to="/home/historial">Abrir historial</Link></div>
      <div className="milestone-grid">
        {recentMilestones.map(({ title, detail, step, tone }) => (
          <div className="milestone" key={title}>
            <span className={`milestone-ring tone-${tone}`} />
            <div><strong>{title}</strong><p>{detail}</p><small>{step}</small></div>
          </div>
        ))}
      </div>
    </section>
  )
}
