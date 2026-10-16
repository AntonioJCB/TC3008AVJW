import { ArrowUpRight, RotateCw } from 'lucide-react'
import { Link } from 'react-router'
import { demoProject } from '../services/demoData'

export default function DashboardHeader({ onNewAnalysis }: { onNewAnalysis: () => void }) {
  return (
    <header className="dashboard-topbar proposal-topbar">
      <div>
        <div className="topbar-eyebrow">ORGANIZACIÓN ANALIZADA · ESCENARIO FICTICIO</div>
        <h1>{demoProject.domain}<span className="domain-verified" aria-label="Dominio de muestra">✓</span></h1>
      </div>
      <div className="proposal-top-actions">
        <span className="sample-status"><span aria-hidden="true" />Datos de ejemplo</span>
        <button className="new-analysis-button" type="button" onClick={onNewAnalysis}><RotateCw size={16} />Nuevo análisis</button>
        <Link className="return-link" to="/login" aria-label="Volver al acceso"><ArrowUpRight size={16} /></Link>
      </div>
    </header>
  )
}
