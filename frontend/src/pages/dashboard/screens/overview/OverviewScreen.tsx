import { demoProject } from '../../services/demoData'
import RiskScoreCard from './components/RiskScoreCard'
import RiskTrendChart from './components/RiskTrendChart'
import { InventoryCard, PriorityFindings, RecentChanges, SeverityCard, SourcesCard, SummaryCard } from './components/OverviewCards'
import './overview.css'

export default function OverviewScreen() {
  return (
    <div className="overview-screen">
      <div className="overview-title-row"><div><h2>Resumen de exposición</h2><p>Qué requiere atención y cómo se relacionan los datos del escenario.</p></div><span className="overview-demo-status"><i /> Muestra estática</span></div>
      <div className="overview-primary-grid"><RiskScoreCard /><SummaryCard /></div>
      <div className="overview-analysis-grid"><RiskTrendChart /><SeverityCard /></div>
      <PriorityFindings />
      <div className="overview-bottom-grid"><InventoryCard /><SourcesCard /></div>
      <RecentChanges />
      <p className="overview-disclaimer">Los {demoProject.assets.length} activos, {demoProject.findings.length} hallazgos y el puntaje de {demoProject.score} son datos ficticios; ningún análisis se ha ejecutado.</p>
    </div>
  )
}
