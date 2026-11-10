import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { loadSourceRawResult, type RawSourceResult, type Source, type SourceResult } from '../../../services/clientData'

type RawState =
  | { status: 'none' | 'loading'; value: null }
  | { status: 'ready'; value: RawSourceResult | null }
  | { status: 'error'; value: null }

function dateTime(value: string | null | undefined) {
  return value ? new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
}

export default function LiveSourceLogDialog({ source, result, statusLabel, duration, onClose }: {
  source: Source
  result: SourceResult | null
  statusLabel: string
  duration: string
  onClose: () => void
}) {
  const dialogRef = useRef<HTMLElement>(null)
  const closeRef = useRef<HTMLButtonElement>(null)
  const rawId = result?.resultado_crudo_id
  const [rawState, setRawState] = useState<RawState>(rawId ? { status: 'loading', value: null } : { status: 'none', value: null })

  useEffect(() => {
    if (!rawId) return
    let active = true
    void loadSourceRawResult(rawId).then((value) => {
      if (active) setRawState({ status: 'ready', value })
    }).catch(() => {
      if (active) setRawState({ status: 'error', value: null })
    })
    return () => { active = false }
  }, [rawId])

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    closeRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return }
      if (event.key !== 'Tab') return
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])')
      if (!focusable?.length) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = previousOverflow
      previousFocus?.focus()
    }
  }, [onClose])

  const discarded = Object.entries(result?.descartadas ?? {}).filter(([, count]) => Number(count) > 0)
  const rawText = rawState.status === 'ready' && rawState.value ? JSON.stringify(rawState.value.contenido, null, 2) : null

  return <div className="source-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section ref={dialogRef} className="source-detail-dialog source-log-dialog" role="dialog" aria-modal="true" aria-labelledby="live-source-dialog-heading" aria-describedby="live-source-dialog-description">
      <button ref={closeRef} type="button" className="source-dialog-close" aria-label="Cerrar registro" onClick={onClose}><X size={18} /></button>
      <span className="source-panel-label">ÚLTIMO ANÁLISIS · REGISTRO DE FUENTE</span>
      <h2 id="live-source-dialog-heading">{source.nombre}</h2>
      <p id="live-source-dialog-description">Estado: <strong>{statusLabel}</strong> · Tipo de acceso: {source.tipo_acceso}</p>

      <div className="source-log-section">
        <h3>Registro de ejecución</h3>
        {result ? <ol className="source-log-events">
          {result.iniciado_en && <li><time>{dateTime(result.iniciado_en)}</time><strong>Consulta iniciada</strong></li>}
          <li><time>{dateTime(result.finalizado_en ?? result.iniciado_en)}</time><strong>{result.estado === 'completado' ? 'Consulta completada' : result.estado === 'fallido' ? 'Consulta fallida' : 'Estado actual: ' + result.estado}</strong><span>{result.error || `${result.observaciones_generadas} observaciones registradas.`}</span></li>
        </ol> : <p>No hay una ejecución registrada para esta fuente en el último análisis terminado.</p>}
      </div>

      {result && <>
        <dl className="source-log-metrics"><div><dt>Duración</dt><dd>{duration}</dd></div><div><dt>Observaciones</dt><dd>{result.observaciones_generadas}</dd></div><div><dt>Nuevas / duplicadas</dt><dd>{result.observaciones_nuevas} / {result.observaciones_duplicadas}</dd></div><div><dt>Activos nuevos / existentes</dt><dd>{result.activos_nuevos} / {result.activos_existentes}</dd></div></dl>
        {discarded.length > 0 && <div className="source-log-section"><h3>Descartes al normalizar</h3><ul className="source-log-discards">{discarded.map(([reason, count]) => <li key={reason}><span>{reason.replaceAll('_', ' ')}</span><strong>{count}</strong></li>)}</ul></div>}
        <div className="source-log-section"><h3>Respuesta original</h3>
          {rawState.status === 'loading' && <p role="status">Cargando respuesta guardada…</p>}
          {rawState.status === 'error' && <p role="alert">No se pudo consultar la respuesta guardada.</p>}
          {rawState.status === 'none' && <p>{result.estado === 'fallido' ? 'La consulta falló antes de guardar una respuesta.' : 'No hay respuesta cruda guardada para esta ejecución.'}</p>}
          {rawState.status === 'ready' && (rawState.value ? <details className="source-log-raw"><summary>Ver JSON recibido · {dateTime(rawState.value.observado_en)}</summary><pre>{rawText}</pre></details> : <p>No se encontró la respuesta guardada para esta ejecución.</p>)}
        </div>
      </>}
    </section>
  </div>
}
