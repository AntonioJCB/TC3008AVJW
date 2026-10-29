import { demoProject } from '../../services/demoData'
import './header.css'

export default function DashboardHeader({ onNewAnalysis }: { onNewAnalysis: () => void }) {
  return (
    <header className="dashboard-topbar proposal-topbar">
      <div>
        <span className="topbar-eyebrow">ORGANIZACIÓN ANALIZADA</span>
        <div className="org-title">
          <h1>{demoProject.domain}</h1>
          <span className="domain-verified" title="Dominio autorizado en la muestra" aria-label="Dominio autorizado en la muestra">✓</span>
        </div>
      </div>
      <div className="proposal-top-actions">
        <span className="analysis-status"><span aria-hidden="true" />Último análisis: {demoProject.lastAnalysis}</span>
        <button className="new-analysis-button" type="button" aria-label="Nuevo análisis" onClick={onNewAnalysis}>
          <span className="analysis-refresh" aria-hidden="true">↻</span>
          <b>Nuevo análisis</b>
        </button>
      </div>
    </header>
  )
}
