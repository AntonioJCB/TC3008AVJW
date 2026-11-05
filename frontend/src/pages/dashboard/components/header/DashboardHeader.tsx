import { demoProject } from '../../services/demoData'
import './header.css'

type HeaderProps = {
  onNewAnalysis: () => void
  domain?: string
  lastAnalysis?: string
  actionLabel?: string
  actionDisabled?: boolean
  domainVerified?: boolean
  organizationName?: string
}

export default function DashboardHeader({ onNewAnalysis, domain, lastAnalysis, actionLabel = 'Nuevo análisis', actionDisabled = false, domainVerified = false, organizationName }: HeaderProps) {
  return (
    <header className="dashboard-topbar proposal-topbar">
      <div>
        <span className="topbar-eyebrow">{organizationName ?? 'ORGANIZACIÓN ANALIZADA'}</span>
        <div className="org-title">
          <h1>{domain ?? demoProject.domain}</h1>
          {(!domain || domainVerified) && <span className="domain-verified" title={domain ? 'Dominio autorizado' : 'Dominio autorizado en la muestra'} aria-label={domain ? 'Dominio autorizado' : 'Dominio autorizado en la muestra'}>✓</span>}
        </div>
      </div>
      <div className="proposal-top-actions">
        <span className="analysis-status"><span aria-hidden="true" />Último análisis: {lastAnalysis ?? demoProject.lastAnalysis}</span>
        <button className="new-analysis-button" type="button" aria-label={actionLabel} onClick={onNewAnalysis} disabled={actionDisabled}>
          <span className="analysis-refresh" aria-hidden="true">↻</span>
          <b>{actionLabel}</b>
        </button>
      </div>
    </header>
  )
}
