import { useEffect, useRef, useState } from 'react'
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

export default function RiskTrendChart() {
  const [range, setRange] = useState<TrendRange>('30D')
  const values = riskTrends[range]
  const [animatedValues, setAnimatedValues] = useState<number[]>(() => sampleTrend(riskTrends['30D']))
  const animatedValuesRef = useRef(animatedValues)
  const line = smoothPath(chartPoints(animatedValues))
  const area = `${line} L 680 190 L 42 190 Z`
  const markerPoints = chartPoints(values)
  const eventPoint = markerPoints[Math.max(0, markerPoints.length - 3)]
  const lastPoint = markerPoints[markerPoints.length - 1]

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
