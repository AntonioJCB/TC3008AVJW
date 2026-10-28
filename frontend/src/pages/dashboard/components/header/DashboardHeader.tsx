import { RotateCw } from 'lucide-react'
import { demoProject } from '../../services/demoData'
import './header.css'

export default function DashboardHeader({ onNewAnalysis }: { onNewAnalysis: () => void }) {
  return (
    <header className="dashboard-topbar proposal-topbar">
      <div>
        <span className="topbar-eyebrow">ORGANIZACIÓN ANALIZADA</span>
        <div className="org-title">
          <h1>{demoProject.domain}</h1>
          <span className="domain-verified" title="Dominio de muestra" aria-label="Dominio de muestra">✓</span>
        </div>
      </div>
      <div className="proposal-top-actions">
        <span className="sample-status"><span aria-hidden="true" />Datos de ejemplo</span>
        <button className="new-analysis-button" type="button" onClick={onNewAnalysis}>
          <RotateCw size={16} aria-hidden="true" />
          <b>Nuevo análisis</b>
        </button>
      </div>
    </header>
  )
}
