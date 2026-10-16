import { useState } from 'react'
import { riskTrends, type TrendRange } from '../services/overviewMock'

function chartPoints(values: readonly number[]) {
  return values.map((value, index) => ({
    x: 34 + index * (570 / (values.length - 1)),
    y: 188 - value * 1.7,
    value,
  }))
}

export default function RiskTrendChart() {
  const [range, setRange] = useState<TrendRange>('30D')
  const points = chartPoints(riskTrends[range])
  const line = points.map(({ x, y }) => `${x},${y}`).join(' ')
  const area = `34,188 ${line} 604,188`
  return (
    <section className="content-card proposal-card trend-card" aria-labelledby="trend-title">
      <div className="card-heading"><div><h3 id="trend-title">EVOLUCIÓN SIMULADA DEL RIESGO</h3><small>Valores ficticios para explorar la gráfica</small></div>
        <div className="trend-ranges" role="group" aria-label="Rango temporal simulado">{(Object.keys(riskTrends) as TrendRange[]).map((item) => <button type="button" key={item} className={range === item ? 'selected' : ''} aria-pressed={range === item} onClick={() => setRange(item)}>{item}</button>)}</div>
      </div>
      <div className="trend-chart" role="img" aria-label={`Puntajes ilustrativos del rango ${range}: ${riskTrends[range].join(', ')}`}>
        <svg viewBox="0 0 640 210" preserveAspectRatio="none" aria-hidden="true">
          <defs><linearGradient id="risk-area" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="var(--teal)" stopOpacity=".24" /><stop offset="100%" stopColor="var(--teal)" stopOpacity="0" /></linearGradient></defs>
          {[52, 103, 154].map((y) => <line key={y} x1="34" x2="604" y1={y} y2={y} className="chart-gridline" />)}
          <polygon points={area} fill="url(#risk-area)" />
          <polyline points={line} fill="none" stroke="var(--teal)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          {points.map(({ x, y, value }, index) => <g key={`${index}-${value}`}><circle cx={x} cy={y} r="5" fill="var(--theme-surface)" stroke="var(--teal)" strokeWidth="3" /><text x={x} y={y - 13} textAnchor="middle" className="chart-value">{value}</text></g>)}
        </svg>
      </div>
    </section>
  )
}
