import { useEffect, useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'
import type { ClientData, Source, SourceResult } from '../../services/clientData'
import './sources.css'

type Filter = 'all' | 'healthy' | 'issues'
type SourceItem = { source: Source; result: SourceResult | null; status: 'healthy' | 'error' | 'pending' | 'running' }

function dateTime(value: string | null | undefined) {
  return value ? new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
}

function duration(result: SourceResult | null) {
  if (!result?.iniciado_en || !result.finalizado_en) return '—'
  const seconds = (new Date(result.finalizado_en).getTime() - new Date(result.iniciado_en).getTime()) / 1000
  return Number.isFinite(seconds) && seconds >= 0 ? `${seconds.toFixed(1)} s` : '—'
}

function state(result: SourceResult | null): SourceItem['status'] {
  if (!result) return 'pending'
  if (result.estado === 'completado') return 'healthy'
  if (result.estado === 'fallido') return 'error'
  return result.estado === 'ejecutando' ? 'running' : 'pending'
}

function stateLabel(status: SourceItem['status']) {
  return { healthy: 'Saludable', error: 'Fallida', running: 'Ejecutando', pending: 'Sin ejecutar' }[status]
}

export default function LiveSourcesScreen({ data, onRefresh }: { data: ClientData; onRefresh: () => void }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const results = useMemo(() => new Map(data.sourceResults.map((result) => [result.fuente_id, result])), [data.sourceResults])
  const items = useMemo<SourceItem[]>(() => data.sources.map((source) => {
    const result = results.get(source.id) ?? null
    return { source, result, status: state(result) }
  }), [data.sources, results])
  const selected = items.find((item) => item.source.id === selectedId) ?? items.find((item) => item.status === 'error') ?? items[0] ?? null
  const healthy = items.filter((item) => item.status === 'healthy').length
  const issues = items.filter((item) => item.status === 'error').length
  const coverage = items.length && data.sourceResults.length ? Math.round(healthy / items.length * 100) : null
  const observations = data.sourceResults.reduce((sum, result) => sum + result.observaciones_generadas, 0)
  const normalized = data.sourceResults.reduce((sum, result) => sum + result.observaciones_nuevas, 0)
  const duplicated = data.sourceResults.reduce((sum, result) => sum + result.observaciones_duplicadas, 0)
  const newAssets = data.sourceResults.reduce((sum, result) => sum + result.activos_nuevos, 0)
  const existingAssets = data.sourceResults.reduce((sum, result) => sum + result.activos_existentes, 0)
  const visible = items.filter((item) => {
    const searchMatches = `${item.source.nombre} ${item.source.tipo_acceso}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())
    return searchMatches && (filter === 'all' || (filter === 'healthy' ? item.status === 'healthy' : item.status === 'error'))
  })
  const latestResponse = data.sourceResults.map((result) => result.finalizado_en).filter((value): value is string => Boolean(value)).sort().at(-1)

  useEffect(() => {
    if (!detailOpen) return
    const onEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setDetailOpen(false) }
    window.addEventListener('keydown', onEscape)
    return () => window.removeEventListener('keydown', onEscape)
  }, [detailOpen])

  return <div className="sources-screen live-sources-screen">
    <header className="sources-header"><div className="sources-header-actions"><span>Última consulta: {dateTime(latestResponse)}</span><button type="button" onClick={onRefresh}>Actualizar fuentes</button></div></header>
    <div className="source-kpis" aria-label="Resumen de fuentes">
      {[
        { label: 'CONECTADAS', value: items.length, detail: 'Fuentes registradas', tone: '' },
        { label: 'SALUDABLES', value: healthy, detail: 'Finalizaron sin incidencias', tone: 'healthy' },
        { label: 'CON INCIDENCIAS', value: issues, detail: 'Fallaron en el último análisis', tone: 'partial' },
        { label: 'COBERTURA', value: coverage === null ? '—' : `${coverage}%`, detail: 'Fuentes completadas', tone: 'coverage' },
      ].map((metric) => <article className={`content-card source-kpi ${metric.tone ? `tone-${metric.tone}` : ''}`} key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small></article>)}
    </div>
    <div className="sources-workspace">
      <section className="content-card source-inventory" aria-labelledby="live-source-inventory-heading">
        <div className="source-inventory-header"><div><h2 id="live-source-inventory-heading">Inventario de fuentes</h2><p>{visible.length} {visible.length === 1 ? 'fuente visible' : 'fuentes visibles'}</p></div><label className="source-search"><Search size={18} aria-hidden="true" /><span className="sr-only">Buscar fuente</span><input type="search" placeholder="Buscar fuente o tipo de dato" value={query} onChange={(event) => setQuery(event.target.value)} />{query && <button type="button" aria-label="Limpiar búsqueda" onClick={() => setQuery('')}><X size={16} /></button>}</label></div>
        <div className="source-filters" role="group" aria-label="Filtrar fuentes">{[
          { id: 'all' as Filter, label: 'Todas', count: items.length },
          { id: 'healthy' as Filter, label: 'Saludables', count: healthy },
          { id: 'issues' as Filter, label: 'Con incidencias', count: issues },
        ].map((option) => <button key={option.id} type="button" className={filter === option.id ? 'active' : ''} aria-pressed={filter === option.id} onClick={() => setFilter(option.id)}>{option.label}<span>{option.count}</span></button>)}</div>
        <div className="source-records-scroller"><div className="source-record-head"><span>FUENTE</span><span>CONTRIBUCIÓN</span><span>RENDIMIENTO</span><span>ESTADO</span></div><div className="source-records">{visible.length ? visible.map((item) => <button type="button" className={`source-record${selected?.source.id === item.source.id ? ' selected' : ''}`} aria-pressed={selected?.source.id === item.source.id} key={item.source.id} onClick={() => setSelectedId(item.source.id)}><span className="source-identity"><span className={`source-monogram ${item.status}`}>{item.source.nombre.replace(/[^a-z]/gi, '').slice(0, 2).toUpperCase()}</span><span><strong>{item.source.nombre}</strong><small>{item.source.tipo_acceso}</small></span></span><span className="source-record-cell"><strong>{item.result ? `${item.result.observaciones_generadas} observaciones` : 'Sin resultados'}</strong><small>{item.result ? `${item.result.activos_nuevos} activos nuevos` : 'Aún no consultada'}</small></span><span className="source-record-cell"><strong>{duration(item.result)}</strong><small>{dateTime(item.result?.finalizado_en)}</small></span><span className={`source-status ${item.status}`}>{stateLabel(item.status)}</span></button>) : <div className="source-empty">No hay fuentes que coincidan con la búsqueda y el filtro.</div>}</div></div>
      </section>
      <aside className="sources-side" aria-label="Calidad y cobertura de fuentes">
        <section className="content-card source-quality" aria-labelledby="live-source-quality-heading"><span className="source-panel-label" id="live-source-quality-heading">LECTURA DE CALIDAD</span>{selected ? <><span className="source-quality-badge">{stateLabel(selected.status).toUpperCase()}</span><h2>{selected.source.nombre}</h2><p>{selected.result?.error || (selected.result ? `Esta fuente terminó en estado «${selected.result.estado}» y generó ${selected.result.observaciones_generadas} observaciones.` : 'Esta fuente todavía no tiene resultados en el último análisis terminado.')}</p><div className="source-quality-facts"><div><span>Observaciones</span><strong>{selected.result?.observaciones_generadas ?? '—'}</strong></div><div><span>Activos nuevos</span><strong>{selected.result?.activos_nuevos ?? '—'}</strong></div><div><span>Duración</span><strong>{duration(selected.result)}</strong></div><div><span>Finalizó</span><strong>{dateTime(selected.result?.finalizado_en)}</strong></div></div><button type="button" className="source-detail-action" onClick={() => setDetailOpen(true)}>Ver detalle técnico</button></> : <p className="source-quality-empty">No hay fuentes registradas.</p>}</section>
        <section className="content-card source-coverage" aria-labelledby="live-source-coverage-heading"><div className="source-card-heading"><h2 id="live-source-coverage-heading">CONTRIBUCIÓN POR FUENTE</h2><strong>{observations} obs.</strong></div>{observations > 0 ? <div className="source-coverage-bars">{items.map((item) => { const percent = Math.round((item.result?.observaciones_generadas ?? 0) / observations * 100); return <div className="source-coverage-row" key={item.source.id}><span>{item.source.nombre}</span><strong>{percent}%</strong><div className="source-coverage-track" role="img" aria-label={`${item.source.nombre}: ${percent}% de las observaciones`}><span style={{ width: `${percent}%` }} /></div></div> })}</div> : <p className="source-quality-empty">Aún no hay observaciones para calcular la contribución.</p>}</section>
        <section className="content-card source-normalization" aria-labelledby="live-source-normalization-heading"><div className="source-card-heading"><h2 id="live-source-normalization-heading">NORMALIZACIÓN</h2><strong>{newAssets} activos nuevos</strong></div><div className="source-normalization-facts"><div><span>Observaciones nuevas</span><strong>{normalized}</strong></div><div><span>Duplicadas</span><strong>{duplicated}</strong></div><div><span>Activos nuevos</span><strong>{newAssets}</strong></div><div><span>Activos existentes</span><strong>{existingAssets}</strong></div></div></section>
      </aside>
    </div>
    {detailOpen && selected && <div className="source-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setDetailOpen(false) }}><section className="source-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="live-source-dialog-heading"><button type="button" className="source-dialog-close" aria-label="Cerrar detalle" onClick={() => setDetailOpen(false)}><X size={18} /></button><span className="source-panel-label">DETALLE TÉCNICO</span><h2 id="live-source-dialog-heading">{selected.source.nombre}</h2><p>{selected.result?.error || 'Resultado registrado para el último análisis terminado.'}</p><dl><div><dt>Tipo de acceso</dt><dd>{selected.source.tipo_acceso}</dd></div><div><dt>Estado</dt><dd>{stateLabel(selected.status)}</dd></div><div><dt>Inicio</dt><dd>{dateTime(selected.result?.iniciado_en)}</dd></div><div><dt>Finalización</dt><dd>{dateTime(selected.result?.finalizado_en)}</dd></div><div><dt>Observaciones</dt><dd>{selected.result?.observaciones_generadas ?? '—'}</dd></div><div><dt>Duración</dt><dd>{duration(selected.result)}</dd></div><div><dt>Duplicadas</dt><dd>{selected.result?.observaciones_duplicadas ?? '—'}</dd></div><div><dt>Descartadas</dt><dd>{selected.result ? Object.values(selected.result.descartadas ?? {}).reduce((sum, value) => sum + Number(value || 0), 0) : '—'}</dd></div></dl></section></div>}
  </div>
}
