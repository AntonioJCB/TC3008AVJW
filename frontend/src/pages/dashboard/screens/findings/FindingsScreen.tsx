import { useState } from 'react'
import { demoProject, type Severity } from '../../services/demoData'
import FindingCard from './components/FindingCard'

const severities: Array<Severity | 'Todos'> = ['Todos', 'Crítico', 'Medio']

export default function FindingsScreen() {
  const [severity, setSeverity] = useState<Severity | 'Todos'>('Todos')
  const findings = demoProject.findings.filter((finding) => severity === 'Todos' || finding.severity === severity)
  return (
    <section className="content-card findings-section" aria-labelledby="findings-title">
      <div className="section-heading"><div><div className="eyebrow">EVALUACIÓN</div><h2 id="findings-title">Hallazgos del escenario</h2><p>Ordenados por severidad para facilitar la revisión.</p></div><span className="count-pill">{findings.length} {findings.length === 1 ? 'hallazgo' : 'hallazgos'}</span></div>
      <div className="severity-filters" aria-label="Filtrar por severidad">{severities.map((item) => <button key={item} className={severity === item ? 'selected' : ''} type="button" onClick={() => setSeverity(item)}>{item}</button>)}</div>
      <div className="finding-list">{findings.map((finding) => <FindingCard finding={finding} key={finding.id} />)}</div>
    </section>
  )
}
