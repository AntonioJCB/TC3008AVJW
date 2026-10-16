import { useState } from 'react'
import { demoProject } from '../../../services/demoData'
import { riskFactors } from '../services/overviewMock'

export default function RiskScoreCard() {
  const [showCalculation, setShowCalculation] = useState(false)
  return (
    <section className="content-card proposal-card risk-card" aria-labelledby="risk-title">
      <div className="card-heading"><h3 id="risk-title">RISK SCORE</h3><span>0–100</span></div>
      <div className="risk-card-body">
        <div className="proposal-score-ring" aria-label={`Puntaje de riesgo ilustrativo: ${demoProject.score} de 100, alto`}>
          <div><strong>{demoProject.score}</strong><span>ALTO</span></div>
        </div>
        <div className="risk-breakdown"><strong className="risk-change">Puntaje del escenario de prueba</strong>
          {riskFactors.map((factor) => <div className="factor-row" key={factor.label}><span className="factor-dot" style={{ background: factor.color }} /><span>{factor.label}</span><strong>{factor.value}</strong></div>)}
          <button className="text-action" type="button" aria-expanded={showCalculation} onClick={() => setShowCalculation((value) => !value)}>Ver desglose ilustrativo</button>
        </div>
      </div>
      {showCalculation && <p className="calculation-note">{riskFactors.map(({ value }) => value).join(' + ')} = {demoProject.score}. Esta suma es una maqueta visual; todavía no existe un motor de riesgo conectado.</p>}
    </section>
  )
}
