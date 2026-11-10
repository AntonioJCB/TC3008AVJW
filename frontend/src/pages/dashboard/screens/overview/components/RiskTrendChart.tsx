import { useEffect, useRef, useState } from 'react'
import type { HistoryScan } from '../../history/services/historyMock'
import { riskTrends, type TrendRange } from '../services/overviewMock'

const sampleCount = 32

function sampleTrend(values: readonly number[]) {
  return Array.from({ length: sampleCount }, (_, index) => {
    const position = (index / (sampleCount - 1)) * (values.length - 1)
    const left = Math.floor(position)
    const right = Math.min(left + 1, values.length - 1)
    return values[left] + (values[right] - values[left]) * (position - left)
  })
}

function chartPoints(values: readonly number[]) {
  return values.map((value, index) => ({
    x: 42 + index * (638 / (values.length - 1)),
    y: 190 - ((value - 20) / 60) * 156,
    value,
  }))
}

function smoothPath(points: ReturnType<typeof chartPoints>) {
  return points.slice(1).reduce((path, point, index) => {
    const previous = points[index]
    const before = points[Math.max(index - 1, 0)]
    const after = points[Math.min(index + 2, points.length - 1)]
    const firstControl = {
      x: previous.x + (point.x - before.x) / 6,
      y: previous.y + (point.y - before.y) / 6,
    }
    const secondControl = {
      x: point.x - (after.x - previous.x) / 6,
      y: point.y - (after.y - previous.y) / 6,
    }
    return `${path} C ${firstControl.x} ${firstControl.y}, ${secondControl.x} ${secondControl.y}, ${point.x} ${point.y}`
  }, `M ${points[0].x} ${points[0].y}`)
}

function localDateKey(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function scoreColor(score: number) {
  if (score >= 75) return 'var(--risk-critical)'
  if (score >= 50) return 'var(--risk-high)'
  if (score >= 25) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

export default function RiskTrendChart({ actualScans }: { actualScans?: HistoryScan[] } = {}) {
  const [range, setRange] = useState<TrendRange>('30D')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const values = riskTrends[range]
  const [animatedValues, setAnimatedValues] = useState<number[]>(() => sampleTrend(riskTrends['30D']))
  const animatedValuesRef = useRef(animatedValues)
  const line = smoothPath(chartPoints(animatedValues))
  const area = `${line} L 680 190 L 42 190 Z`
  const markerPoints = chartPoints(values)
  const eventPoint = markerPoints[Math.max(0, markerPoints.length - 3)]
  const lastPoint = markerPoints[markerPoints.length - 1]

  const invalidDateRange = Boolean(dateFrom && dateTo && dateFrom > dateTo)
  const filteredScans = actualScans?.filter((scan) => {
    if (invalidDateRange) return false
    const day = scan.occurredAt ? localDateKey(scan.occurredAt) : null
    if (!day) return !dateFrom && !dateTo
    return (!dateFrom || day >= dateFrom) && (!dateTo || day <= dateTo)
  })
  const actualPoints = filteredScans?.map((scan, index) => ({
    x: filteredScans.length === 1 ? 361 : 42 + index * (638 / (filteredScans.length - 1)),
    y: 190 - Math.max(0, Math.min(100, scan.score)) / 100 * 156,
    ...scan,
  }))

  useEffect(() => {
    const from = animatedValuesRef.current
    const to = sampleTrend(riskTrends[range])
    if (from.every((value, index) => value === to[index])) return

    const duration = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 650
    let frame = 0
    let started: number | undefined

    const animate = (now: number) => {
      started ??= now
      const progress = duration === 0 ? 1 : Math.min((now - started) / duration, 1)
      const eased = 1 - (1 - progress) ** 3
      const next = from.map((value, index) => value + (to[index] - value) * eased)
      animatedValuesRef.current = next
      setAnimatedValues(next)
      if (progress < 1) frame = window.requestAnimationFrame(animate)
    }

    frame = window.requestAnimationFrame(animate)
    return () => window.cancelAnimationFrame(frame)
  }, [range])

  if (actualPoints) {
    const hasDateFilter = Boolean(dateFrom || dateTo)
    const labelStep = Math.max(1, Math.ceil(actualPoints.length / 5))
    const showAllValues = actualPoints.length <= 20
    const completeCount = filteredScans?.filter((scan) => scan.status === 'completado').length ?? 0
    const partialCount = filteredScans?.filter((scan) => scan.status === 'incompleto').length ?? 0
    const failedCount = filteredScans?.filter((scan) => scan.status === 'fallido').length ?? 0

    return (
      <section className="content-card proposal-card trend-card" aria-labelledby="trend-title">
        <div className="card-heading">
          <h3 id="trend-title">EVOLUCIÓN DEL RIESGO</h3>
          <div className="trend-date-filter" role="group" aria-label="Filtrar análisis por fechas">
            <label>Desde<input type="date" value={dateFrom} max={dateTo || undefined} onChange={(event) => setDateFrom(event.target.value)} /></label>
            <label>Hasta<input type="date" value={dateTo} min={dateFrom || undefined} onChange={(event) => setDateTo(event.target.value)} /></label>
            {hasDateFilter && <button type="button" onClick={() => { setDateFrom(''); setDateTo('') }}>Ver todo</button>}
          </div>
        </div>
        {actualPoints.length ? <>
          <div className="trend-chart"><svg viewBox="0 0 700 240" role="img" aria-label={`Puntajes del periodo: ${filteredScans?.map((scan) => `${scan.date}, ${scan.score} puntos, ${scan.status ?? 'completado'}`).join('; ')}`}>
            <defs><linearGradient id="live-risk-scale" x1="0" y1="34" x2="0" y2="190" gradientUnits="userSpaceOnUse"><stop offset="0%" stopColor="var(--risk-critical)" /><stop offset="25%" stopColor="var(--risk-high)" /><stop offset="50%" stopColor="var(--risk-medium)" /><stop offset="75%" stopColor="var(--risk-low)" /><stop offset="100%" stopColor="var(--risk-low)" /></linearGradient></defs>
            {[0, 25, 50, 75, 100].map((value) => { const y = 190 - value / 100 * 156; return <g key={value}><line x1="42" x2="680" y1={y} y2={y} className="chart-gridline" /><text x="10" y={y + 4} className="axis-label">{value}</text></g> })}
            {actualPoints.slice(1).map((point, index) => { const previous = actualPoints[index]; const partial = previous.status !== 'completado' || point.status !== 'completado'; return <path key={index} d={`M ${previous.x} ${previous.y} L ${point.x} ${point.y}`} className={`trend-line ${partial ? 'partial' : 'risk'}`} /> })}
            {actualPoints.map((point, index) => {
              const showDate = actualPoints.length <= 6 || index === 0 || index === actualPoints.length - 1 || index % labelStep === 0
              return <g key={`${point.occurredAt ?? point.date}-${index}`}><title>{point.date}{point.occurredAt ? `, ${new Date(point.occurredAt).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' })}` : ''}: {point.score} puntos ({point.status ?? 'completado'})</title><circle cx={point.x} cy={point.y} r="5" className={`chart-point ${point.status ?? 'completado'}`} style={point.status === 'completado' ? { stroke: scoreColor(point.score) } : undefined} />{showAllValues && <text x={point.x} y={Math.max(20, point.y - 13)} textAnchor="middle" className="chart-value" style={point.status === 'completado' ? { fill: scoreColor(point.score) } : undefined}>{point.score}</text>}{showDate && <text x={point.x} y="222" textAnchor="middle" className="chart-date">{point.date}</text>}</g>
            })}
          </svg></div>
          <div className="trend-status-legend" aria-label="Estado de los análisis"><span><i className="completado" />Completos {completeCount}</span><span><i className="incompleto" />Parciales {partialCount}</span><span><i className="fallido" />Fallidos {failedCount}</span></div>
        </> : <p className="client-empty" role="status">{invalidDateRange ? 'La fecha inicial debe ser anterior o igual a la final.' : hasDateFilter ? 'No hay análisis con puntaje en estas fechas.' : 'El historial aparecerá después del primer análisis.'}</p>}
      </section>
    )
  }

  return (
    <section className="content-card proposal-card trend-card" aria-labelledby="trend-title">
      <div className="card-heading">
        <h3 id="trend-title">EVOLUCIÓN DEL RIESGO</h3>
        <div className="trend-ranges" role="group" aria-label="Rango temporal simulado">
          {(Object.keys(riskTrends) as TrendRange[]).map((item) => (
            <button type="button" key={item} className={range === item ? 'selected' : ''} aria-pressed={range === item} onClick={() => setRange(item)}>{item}</button>
          ))}
        </div>
      </div>
      <div className="trend-chart">
        <svg viewBox="0 0 700 220" role="img" aria-label={`Puntajes ilustrativos del rango ${range}: ${values.join(', ')}`}>
          <defs><linearGradient id="overview-trend-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--teal)" stopOpacity=".22" /><stop offset="100%" stopColor="var(--teal)" stopOpacity="0" /></linearGradient></defs>
          {[34, 86, 138, 190].map((y, index) => (
            <g key={y}><line x1="42" x2="680" y1={y} y2={y} className="chart-gridline" /><text x="10" y={y + 4} className="axis-label">{80 - index * 20}</text></g>
          ))}
          <path d={area} className="trend-area" />
          <path d={line} className="trend-line" />
          <g key={range} className="chart-markers">
            <g className="chart-event"><line x1={eventPoint.x} x2={eventPoint.x} y1={eventPoint.y} y2={eventPoint.y - 42} /><text x={eventPoint.x - 35} y={eventPoint.y - 50}>Nuevo servicio</text></g>
            <g className="chart-event"><line x1={lastPoint.x} x2={lastPoint.x} y1={lastPoint.y} y2={lastPoint.y - 37} /><text x={lastPoint.x - 100} y={lastPoint.y - 44}>Subdominio admin</text></g>
            {markerPoints.map(({ x, y, value }, index) => (
              <g key={`${index}-${value}`}>
                <circle cx={x} cy={y} r="5" className="chart-point" />
                {index !== markerPoints.length - 2 && <text x={x} y={y - 13} textAnchor="middle" className="chart-value">{value}</text>}
              </g>
            ))}
          </g>
        </svg>
      </div>
    </section>
  )
}
