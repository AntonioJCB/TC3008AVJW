import { historyRanges, type HistoryRange, type HistoryScan } from '../services/historyMock'

const ranges: HistoryRange[] = ['7D', '30D', '90D']
const xStart = 54
const xEnd = 730
const yTop = 28
const yBase = 206
const scoreY = (score: number) => yBase - Math.max(0, Math.min(100, score)) / 100 * (yBase - yTop)

function chartPoints(scans: HistoryScan[]) {
  return scans.map((scan, index) => ({
    ...scan,
    x: scans.length === 1 ? (xStart + xEnd) / 2 : xStart + ((xEnd - xStart) * index) / (scans.length - 1),
    y: scoreY(scan.score),
  }))
}

function curve(points: ReturnType<typeof chartPoints>) {
  return points.slice(1).reduce((path, point, index) => {
    const previous = points[index]
    const middle = (previous.x + point.x) / 2
    return `${path} C ${middle} ${previous.y}, ${middle} ${point.y}, ${point.x} ${point.y}`
  }, `M ${points[0].x} ${points[0].y}`)
}

function segment(previous: ReturnType<typeof chartPoints>[number], point: ReturnType<typeof chartPoints>[number]) {
  const middle = (previous.x + point.x) / 2
  return `M ${previous.x} ${previous.y} C ${middle} ${previous.y}, ${middle} ${point.y}, ${point.x} ${point.y}`
}

export default function HistoryChart({ range, onRangeChange, scanRanges = historyRanges, live = false }: { range: HistoryRange; onRangeChange: (range: HistoryRange) => void; scanRanges?: Record<HistoryRange, HistoryScan[]>; live?: boolean }) {
  const currentScans = scanRanges[range]
  return <section className="content-card history-chart-card" aria-labelledby="history-chart-title">
    <div className="history-chart-heading">
      <div><h2 id="history-chart-title">EVOLUCIÓN DEL RISK SCORE</h2><p>Se muestran todos los análisis con puntaje. Un 0 parcial o fallido no confirma riesgo nulo.</p></div>
      <div className="history-range" role="group" aria-label="Rango histórico">
        {ranges.map((option) => <button key={option} type="button" aria-pressed={range === option} className={range === option ? 'active' : ''} onClick={() => onRangeChange(option)}>{option}</button>)}
      </div>
    </div>
    {live && <div className="history-chart-legend" aria-label="Estado de los análisis"><span><i className="completado" />Completo</span><span><i className="incompleto" />Parcial</span><span><i className="fallido" />Fallido</span><span className="history-chart-legend-note">Los tramos punteados incluyen resultados incompletos.</span></div>}
    <div className="history-chart-wrap">
      {currentScans.length ? <svg viewBox="0 0 760 260" role="img" aria-label={`Risk Score de ${currentScans[0].score} a ${currentScans.at(-1)!.score} en ${currentScans.length} análisis`}>
        <defs><linearGradient id="history-area-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" className="history-area-start" /><stop offset="1" className="history-area-end" /></linearGradient></defs>
        <g className="history-grid-lines">{[100, 75, 50, 25, 0].map((value) => { const y = scoreY(value); return <g key={value}><line x1={xStart} y1={y} x2={xEnd} y2={y} /><text x="18" y={y + 4}>{value}</text></g> })}</g>
        {ranges.map((option) => {
          const points = chartPoints(scanRanges[option])
          if (!points.length) return null
          const line = curve(points)
          return <g key={option} className={`history-chart-layer${range === option ? ' active' : ''}`} aria-hidden={range !== option}>
            {!live && points.length > 1 && <path className="history-chart-area" d={`${line} L ${points.at(-1)!.x} ${yBase} L ${points[0].x} ${yBase} Z`} />}
            {points.slice(1).map((point, index) => {
              const previous = points[index]
              const status = !live || (previous.status ?? 'completado') === 'completado' && (point.status ?? 'completado') === 'completado' ? 'completado' : previous.status === 'fallido' || point.status === 'fallido' ? 'fallido' : 'incompleto'
              return <path key={`${index}-${index + 1}`} className={`history-chart-line ${status}`} d={segment(previous, point)} />
            })}
            {points.map((point, index) => <g key={`${point.date}-${index}`}>
              <title>{point.date}{point.occurredAt ? `, ${new Date(point.occurredAt).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' })}` : ''}: ${point.score} puntos ({point.status ?? 'completado'})</title>
              <circle className={`history-chart-point ${point.status ?? 'completado'}${index === points.length - 1 ? ' current' : ''}`} cx={point.x} cy={point.y} r={index === points.length - 1 ? 6 : 5} />
              {(points.length <= 12 || index === 0 || index === points.length - 1 || index % Math.ceil(points.length / 6) === 0) && <text className="history-chart-value" x={point.x} y={Math.max(15, point.y - 14)} textAnchor="middle">{point.score}</text>}
              {(points.length <= 12 || index === 0 || index === points.length - 1 || index % Math.ceil(points.length / 6) === 0) && <text className="history-chart-date" x={point.x} y="235" textAnchor="middle">{point.date}</text>}
              {point.marker && option !== '7D' && <g className="history-chart-marker"><line x1={point.x} x2={point.x} y1={point.y - 7} y2={Math.max(12, point.y - 35)} /><text x={point.x} y={Math.max(11, point.y - 43)} textAnchor={point.x > 600 ? 'end' : 'middle'}>{point.marker}</text></g>}
            </g>)}
          </g>
        })}
      </svg> : <p className="history-empty">No hay análisis con puntaje en este periodo.</p>}
    </div>
  </section>
}
