import RiskScoreCard from './components/RiskScoreCard'
import RiskTrendChart from './components/RiskTrendChart'
import { InventoryCard, PriorityFindings, RecentChanges, SeverityCard, SourcesCard, SummaryCard } from './components/OverviewCards'
import './overview.css'

export default function OverviewScreen() {
  return (
    <div className="overview-screen">
      <h2 className="sr-only">Resumen de exposición</h2>
      <div className="overview-primary-grid"><RiskScoreCard /><SummaryCard /></div>
      <div className="overview-analysis-grid"><RiskTrendChart /><SeverityCard /></div>
      <PriorityFindings />
      <div className="overview-bottom-grid"><InventoryCard /><SourcesCard /></div>
      <RecentChanges />
      <p className="overview-disclaimer">Vista estática de la propuesta visual. Las cifras, fuentes, tiempos y hallazgos son ficticios; ningún análisis se ha ejecutado.</p>
    </div>
  )
}
