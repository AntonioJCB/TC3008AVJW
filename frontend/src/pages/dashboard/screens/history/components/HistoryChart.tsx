import { useState } from 'react'
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

function localDateKey(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

function scoreColor(score: number) {
  if (score >= 75) return 'var(--risk-critical)'
  if (score >= 50) return 'var(--risk-high)'
  if (score >= 25) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

export default function HistoryChart({ scans }: { scans?: HistoryScan[] }) {
  const [demoRange, setDemoRange] = useState<HistoryRange>('30D')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const live = scans !== undefined
  const hasDateFilter = Boolean(dateFrom || dateTo)
  const invalidDateRange = Boolean(dateFrom && dateTo && dateFrom > dateTo)
  const currentScans = scans ? scans.filter((scan) => {
    if (invalidDateRange) return false
    const day = scan.occurredAt ? localDateKey(scan.occurredAt) : null
    if (!day) return !hasDateFilter
    return (!dateFrom || day >= dateFrom) && (!dateTo || day <= dateTo)
  }) : historyRanges[demoRange]
  const points = chartPoints(currentScans)
  const showAllValues = points.length <= 20
  const labelStep = Math.max(1, Math.ceil(points.length / 5))
  const completeCount = currentScans.filter((scan) => (scan.status ?? 'completado') === 'completado').length
  const partialCount = currentScans.filter((scan) => scan.status === 'incompleto').length
  const failedCount = currentScans.filter((scan) => scan.status === 'fallido').length
  const line = points.length ? curve(points) : ''

  return <section className="content-card history-chart-card" aria-labelledby="history-chart-title">
    <div className="history-chart-heading">
      <h2 id="history-chart-title">EVOLUCIÓN DEL RISK SCORE</h2>
      {live ? <div className="history-date-filter" role="group" aria-label="Filtrar análisis por fechas">
        <label>Desde<input type="date" value={dateFrom} max={dateTo || undefined} onChange={(event) => setDateFrom(event.target.value)} /></label>
        <label>Hasta<input type="date" value={dateTo} min={dateFrom || undefined} onChange={(event) => setDateTo(event.target.value)} /></label>
        {hasDateFilter && <button type="button" onClick={() => { setDateFrom(''); setDateTo('') }}>Ver todo</button>}
      </div> : <div className="history-range" role="group" aria-label="Rango histórico">
        {ranges.map((option) => <button key={option} type="button" aria-pressed={demoRange === option} className={demoRange === option ? 'active' : ''} onClick={() => setDemoRange(option)}>{option}</button>)}
      </div>}
    </div>
    {live && <div className="history-chart-legend" aria-label="Estado de los análisis"><span><i className="completado" />Completo</span><span><i className="incompleto" />Parcial</span><span><i className="fallido" />Fallido</span><span className="history-chart-legend-note">Los tramos punteados incluyen resultados incompletos.</span></div>}
    <div className="history-chart-wrap">
      {points.length ? <svg viewBox="0 0 760 260" role="img" aria-label={`Puntajes del periodo: ${currentScans.map((scan) => `${scan.date}, ${scan.score} puntos, ${scan.status ?? 'completado'}`).join('; ')}`}>
        <defs>
          <linearGradient id="history-area-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0" className="history-area-start" /><stop offset="1" className="history-area-end" /></linearGradient>
          <linearGradient id="history-risk-scale" x1="0" y1={yTop} x2="0" y2={yBase} gradientUnits="userSpaceOnUse"><stop offset="0%" stopColor="var(--risk-critical)" /><stop offset="25%" stopColor="var(--risk-high)" /><stop offset="50%" stopColor="var(--risk-medium)" /><stop offset="75%" stopColor="var(--risk-low)" /><stop offset="100%" stopColor="var(--risk-low)" /></linearGradient>
        </defs>
        <g className="history-grid-lines">{[100, 75, 50, 25, 0].map((value) => { const y = scoreY(value); return <g key={value}><line x1={xStart} y1={y} x2={xEnd} y2={y} /><text x="18" y={y + 4}>{value}</text></g> })}</g>
        {!live && points.length > 1 && <path className="history-chart-area" d={`${line} L ${points.at(-1)!.x} ${yBase} L ${points[0].x} ${yBase} Z`} />}
        {points.slice(1).map((point, index) => {
          const previous = points[index]
          const status = (previous.status ?? 'completado') === 'completado' && (point.status ?? 'completado') === 'completado' ? 'scored' : previous.status === 'fallido' || point.status === 'fallido' ? 'fallido' : 'incompleto'
          return <path key={`${index}-${index + 1}`} className={`history-chart-line ${status}`} d={segment(previous, point)} />
        })}
        {points.map((point, index) => {
          const complete = (point.status ?? 'completado') === 'completado'
          const showDate = points.length <= 6 || index === 0 || index === points.length - 1 || index % labelStep === 0
          return <g key={`${point.occurredAt ?? point.date}-${index}`}>
            <title>{point.date}{point.occurredAt ? `, ${new Date(point.occurredAt).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' })}` : ''}: {point.score} puntos ({point.status ?? 'completado'})</title>
            <circle className={`history-chart-point ${point.status ?? 'completado'}${index === points.length - 1 ? ' current' : ''}`} cx={point.x} cy={point.y} r={index === points.length - 1 ? 6 : 5} style={complete ? { stroke: scoreColor(point.score) } : undefined} />
            {showAllValues && <text className="history-chart-value" x={point.x} y={Math.max(15, point.y - 14)} textAnchor="middle" style={complete ? { fill: scoreColor(point.score) } : undefined}>{point.score}</text>}
            {showDate && <text className="history-chart-date" x={point.x} y="235" textAnchor="middle">{point.date}</text>}
            {point.marker && !live && demoRange !== '7D' && <g className="history-chart-marker"><line x1={point.x} x2={point.x} y1={point.y - 7} y2={Math.max(12, point.y - 35)} /><text x={point.x} y={Math.max(11, point.y - 43)} textAnchor={point.x > 600 ? 'end' : 'middle'}>{point.marker}</text></g>}
          </g>
        })}
      </svg> : <p className="history-empty" role="status">{invalidDateRange ? 'La fecha inicial debe ser anterior o igual a la final.' : hasDateFilter ? 'No hay análisis en estas fechas.' : 'No hay análisis registrados.'}</p>}
    </div>
    {live && points.length > 0 && <div className="history-chart-legend" aria-label="Estado de los análisis"><span><i className="completado" />Completos {completeCount}</span><span><i className="incompleto" />Parciales {partialCount}</span><span><i className="fallido" />Fallidos {failedCount}</span></div>}
  </section>
}
