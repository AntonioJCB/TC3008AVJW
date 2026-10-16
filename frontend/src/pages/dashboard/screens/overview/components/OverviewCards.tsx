import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router'
import { demoProject, plannedSources } from '../../../services/demoData'
import { inventorySummary, recentMilestones, severitySummary } from '../services/overviewMock'

export function SummaryCard() {
  const total = demoProject.assets.length
  const critical = demoProject.findings.filter((finding) => finding.severity === 'Crítico').length
  return (
    <section className="content-card proposal-card analysis-summary" aria-labelledby="summary-title">
      <div className="card-heading"><div><h3 id="summary-title">RESUMEN DEL ANÁLISIS</h3><small>Datos normalizados del escenario ficticio.</small></div><span className="card-state">Demo preparada</span></div>
      <div className="summary-numbers">
        <div><strong>{total}</strong><span>Activos</span></div>
        <div><strong>{demoProject.findings.length}</strong><span>Hallazgos</span></div>
        <div><strong>{critical}</strong><span>Crítico</span></div>
        <div><strong>{plannedSources.length}</strong><span>Fuentes previstas</span></div>
      </div>
      <div className="summary-detail"><span>Inventario de ejemplo</span><span>Sin escaneo realizado</span><span>Sin fuentes conectadas</span></div>
    </section>
  )
}

export function SeverityCard() {
  const max = Math.max(...severitySummary.map(({ count }) => count), 1)
  return (
    <section className="content-card proposal-card severity-card" aria-labelledby="severity-title">
      <div className="card-heading"><h3 id="severity-title">HALLAZGOS POR SEVERIDAD</h3><Link to="/home/hallazgos">Ver todos</Link></div>
      <div className="severity-bars">{severitySummary.map(({ label, count, tone }) => <div className="severity-bar-row" key={label}><span>{label}</span><div className="bar-track"><i className={`tone-${tone}`} style={{ width: `${(count / max) * 100}%` }} /></div><strong>{count}</strong></div>)}</div>
    </section>
  )
}

export function PriorityFindings() {
  return (
    <section className="content-card proposal-card priorities-card" aria-labelledby="priorities-title">
      <div className="card-heading"><h3 id="priorities-title">HALLAZGOS PRIORITARIOS</h3><Link to="/home/hallazgos">Ver todos los hallazgos <ArrowRight size={14} /></Link></div>
      <div className="priority-table-wrap"><table className="priority-table"><thead><tr><th>SEVERIDAD</th><th>HALLAZGO</th><th>ACTIVO</th><th>ESTADO</th></tr></thead><tbody>
        {demoProject.findings.map((finding) => <tr key={finding.id}><td><span className={`priority-severity ${finding.severity === 'Crítico' ? 'critical' : 'medium'}`}>{finding.severity}</span></td><td><strong>{finding.title}</strong></td><td>{finding.target}</td><td>Ejemplo</td></tr>)}
      </tbody></table></div>
    </section>
  )
}

export function InventoryCard() {
  const max = Math.max(...inventorySummary.map(({ count }) => count))
  return (
    <section className="content-card proposal-card inventory-card" aria-labelledby="inventory-title">
      <div className="card-heading"><h3 id="inventory-title">INVENTARIO DE ACTIVOS</h3><Link to="/home/activos">Explorar activos</Link></div>
      <div className="inventory-bars">{inventorySummary.map(({ label, count, tone }) => <div className="inventory-bar-row" key={label}><span>{label}</span><strong>{count}</strong><div className="bar-track"><i className={`tone-${tone}`} style={{ width: `${(count / max) * 100}%` }} /></div></div>)}</div>
    </section>
  )
}

export function SourcesCard() {
  return (
    <section className="content-card proposal-card sources-card" aria-labelledby="sources-title">
      <div className="card-heading"><h3 id="sources-title">FUENTES PREVISTAS</h3><Link to="/home/fuentes">Detalles</Link></div>
      <div className="planned-source-list">{plannedSources.map((source) => <div key={source}><span className="source-plan-dot" /><strong>{source}</strong><span>Pendiente</span></div>)}</div>
      <div className="sources-foot"><span>Integración de colectores</span><strong>0 / {plannedSources.length}</strong></div>
      <div className="source-progress" /><p>Los nombres representan fuentes planeadas. Todavía no se han consultado.</p>
    </section>
  )
}

export function RecentChanges() {
  return (
    <section className="content-card proposal-card changes-card" aria-labelledby="changes-title">
      <div className="card-heading"><h3 id="changes-title">RECORRIDO DE LA DEMOSTRACIÓN</h3><Link to="/home/historial">Abrir historial</Link></div>
      <div className="milestone-grid">{recentMilestones.map(({ title, detail, step, tone }) => <div className="milestone" key={title}><span className={`milestone-ring tone-${tone}`} /><div><strong>{title}</strong><p>{detail}</p><small>{step}</small></div></div>)}</div>
    </section>
  )
}
