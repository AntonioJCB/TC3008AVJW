import { historyRanges, type HistoryRange, type HistoryScan } from '../services/historyMock'

const ranges: HistoryRange[] = ['7D', '30D', '90D']
const xStart = 54
const xEnd = 730
const yBase = 206

function chartPoints(scans: HistoryScan[]) {
  return scans.map((scan, index) => ({
    ...scan,
    x: xStart + ((xEnd - xStart) * index) / (scans.length - 1),
    y: yBase - (scan.score - 20) * 2.8,
  }))
}

function curve(points: ReturnType<typeof chartPoints>) {
  return points.slice(1).reduce((path, point, index) => {
    const previous = points[index]
    const middle = (previous.x + point.x) / 2
    return `${path} C ${middle} ${previous.y}, ${middle} ${point.y}, ${point.x} ${point.y}`
  }, `M ${points[0].x} ${points[0].y}`)
}

export default function HistoryChart({ range, onRangeChange }: { range: HistoryRange; onRangeChange: (range: HistoryRange) => void }) {
  const currentScans = historyRanges[range]
  return <section className="content-card history-chart-card" aria-labelledby="history-chart-title">
    <div className="history-chart-heading">
      <div><h2 id="history-chart-title">EVOLUCIÓN DEL RISK SCORE</h2><p>La línea conecta análisis completos; los marcadores explican los cambios relevantes.</p></div>
      <div className="history-range" role="group" aria-label="Rango histórico">
        {ranges.map((option) => <button key={option} type="button" aria-pressed={range === option} className={range === option ? 'active' : ''} onClick={() => onRangeChange(option)}>{option}</button>)}
      </div>
    </div>
    <div className="history-chart-wrap">
      <svg viewBox="0 0 760 260" role="img" aria-label={`Risk Score de ${currentScans[0].score} a ${currentScans.at(-1)!.score} en ${currentScans.length} análisis`}>
        <defs><linearGradient id="history-area-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" className="history-area-start" /><stop offset="1" className="history-area-end" /></linearGradient></defs>
        <g className="history-grid-lines">{[80, 60, 40, 20].map((value) => { const y = yBase - (value - 20) * 2.8; return <g key={value}><line x1={xStart} y1={y} x2={xEnd} y2={y} /><text x="18" y={y + 4}>{value}</text></g> })}</g>
        {ranges.map((option) => {
          const points = chartPoints(historyRanges[option])
          const line = curve(points)
          return <g key={option} className={`history-chart-layer${range === option ? ' active' : ''}`} aria-hidden={range !== option}>
            <path className="history-chart-area" d={`${line} L ${xEnd} ${yBase} L ${xStart} ${yBase} Z`} />
            <path className="history-chart-line" d={line} />
            {points.map((point, index) => <g key={`${point.date}-${index}`}>
              <circle className={index === points.length - 1 ? 'history-chart-point current' : 'history-chart-point'} cx={point.x} cy={point.y} r={index === points.length - 1 ? 6 : 5} />
              {(option !== '90D' || index % 2 === 0 || index === points.length - 1) && <text className="history-chart-value" x={point.x} y={point.y - 14} textAnchor="middle">{point.score}</text>}
              {(option !== '90D' || index % 2 === 0 || index === points.length - 1) && <text className="history-chart-date" x={point.x} y="235" textAnchor="middle">{point.date}</text>}
              {point.marker && option !== '7D' && <g className="history-chart-marker"><line x1={point.x} x2={point.x} y1={point.y - 7} y2={Math.max(12, point.y - 35)} /><text x={point.x} y={Math.max(11, point.y - 43)} textAnchor={point.x > 600 ? 'end' : 'middle'}>{point.marker}</text></g>}
            </g>)}
          </g>
        })}
      </svg>
    </div>
  </section>
}
