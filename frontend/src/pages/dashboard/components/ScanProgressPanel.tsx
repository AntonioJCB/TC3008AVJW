import { useEffect, useState } from 'react'
import { Activity, Clock3, Square } from 'lucide-react'
import type { ScanProgress } from '../services/scanActions'
import './scanProgressPanel.css'

type SourceProgress = ScanProgress['fuentes'][number]

function secondsBetween(start: string | null, end: string | null, now: number) {
  if (!start) return 0
  const elapsed = ((end ? new Date(end).getTime() : now) - new Date(start).getTime()) / 1000
  return Number.isFinite(elapsed) ? Math.max(0, elapsed) : 0
}

function duration(seconds: number) {
  const whole = Math.floor(seconds)
  return whole < 60 ? `${whole} s` : `${Math.floor(whole / 60)} min ${String(whole % 60).padStart(2, '0')} s`
}

function sourceState(source: SourceProgress) {
  if (source.error === 'Detenido por el usuario') return { label: 'Detenida', tone: 'stopped' }
  if (source.estado === 'completado') return { label: 'Completada', tone: 'done' }
  if (source.estado === 'fallido') return { label: 'Fallida', tone: 'failed' }
  return { label: 'En curso', tone: 'running' }
}

export default function ScanProgressPanel({ progress, canStop, stopping, onStop }: {
  progress: ScanProgress
  canStop: boolean
  stopping: boolean
  onStop: () => void
}) {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  const sources = progress.fuentes ?? []
  const finished = sources.filter((source) => source.estado === 'completado' || source.estado === 'fallido').length
  const successful = sources.filter((source) => source.estado === 'completado').length
  const observations = sources.reduce((sum, source) => sum + (source.observaciones_generadas || 0), 0)
  const elapsed = secondsBetween(progress.iniciado_en, progress.finalizado_en, now)
  const timeline = sources.map((source) => ({
    ...source,
    seconds: secondsBetween(source.iniciado_en ?? progress.iniciado_en, source.finalizado_en, now),
  }))
  const axis = Math.max(30, Math.ceil(Math.max(elapsed, ...timeline.map((source) => source.seconds)) / 30) * 30)
  const percentage = sources.length ? Math.round(finished / sources.length * 100) : 0

  return <section className="scan-progress-panel" aria-labelledby="scan-progress-title">
    <div className="scan-progress-header">
      <div><span className="scan-progress-eyebrow"><Activity size={16} aria-hidden="true" /> ANÁLISIS EN VIVO</span><h2 id="scan-progress-title">Análisis en ejecución</h2><p>{progress.dominio || 'Las fuentes OSINT están consultando el dominio autorizado.'}</p></div>
      {canStop && <button className="scan-stop-button" type="button" onClick={onStop} disabled={stopping}><Square size={15} fill="currentColor" aria-hidden="true" />{stopping ? 'Deteniendo…' : 'Detener análisis'}</button>}
    </div>
    <div className="scan-progress-summary"><div><span>FUENTES TERMINADAS</span><strong>{finished}<small> / {sources.length}</small></strong></div><div><span>COMPLETADAS</span><strong>{successful}</strong></div><div><span>OBSERVACIONES</span><strong>{observations}</strong></div><div><span>TIEMPO TRANSCURRIDO</span><strong className="scan-elapsed"><Clock3 size={18} aria-hidden="true" />{duration(elapsed)}</strong></div></div>
    <div className="scan-overall"><div><span>Avance de fuentes</span><strong>{percentage}%</strong></div><div className="scan-overall-track" role="progressbar" aria-label="Fuentes terminadas" aria-valuenow={finished} aria-valuemin={0} aria-valuemax={sources.length || 4}><span style={{ width: `${percentage}%` }} /></div><small>{progress.mensaje}</small></div>
    <div className="scan-chart-heading"><div><h3>Rendimiento por fuente</h3><p>Duración de cada consulta y observaciones recibidas</p></div><span>ESCALA · {duration(axis)}</span></div>
    <div className="scan-timeline" role="list" aria-label="Duración de las fuentes OSINT">
      {timeline.map((source) => {
        const state = sourceState(source)
        return <div className="scan-timeline-row" role="listitem" key={source.fuente}>
          <div className="scan-source-heading"><strong>{source.fuente}</strong><span className={`scan-source-state ${state.tone}`}>{state.label}</span></div>
          <div className="scan-source-bar"><span className={`scan-source-fill ${state.tone}`} style={{ width: `${Math.min(100, source.seconds / axis * 100)}%` }} /></div>
          <div className="scan-source-facts"><span>{duration(source.seconds)}</span><span>{source.estado === 'completado' ? `${source.observaciones_generadas || 0} observaciones` : source.error || 'Consultando…'}</span></div>
        </div>
      })}
    </div>
  </section>
}
