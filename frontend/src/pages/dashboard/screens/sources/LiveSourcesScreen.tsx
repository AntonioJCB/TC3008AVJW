import { useCallback, useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'
import { scanSources, type ClientData, type Source, type SourceResult } from '../../services/clientData'
import type { ClientData, Source, SourceResult } from '../../services/clientData'
import { isDisabledSourceResult, sourceIssueSummary } from '../../services/sourcePolicy'
import InfoTip from '../../components/InfoTip'
import LiveSourceLogDialog from './components/LiveSourceLogDialog'
import './sources.css'

type Filter = 'all' | 'healthy' | 'issues'
type SourceItem = { source: Source; result: SourceResult | null; status: 'healthy' | 'partial' | 'error' | 'pending' | 'running' | 'disabled' }
const modules: Record<string, string> = {
  'crt.sh': 'Certificate Transparency',
  theHarvester: 'CertSpotter · HackerTarget · RapidDNS · urlscan',
  SpiderFoot: 'DNS DoH · urlscan · RDAP · Common Crawl',
  Web: 'HTTPS/TLS · certificado · redirección HTTP',
}

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
  if (isDisabledSourceResult(result)) return 'disabled'
  if (result.estado === 'completado') return result.error ? 'partial' : 'healthy'
  if (result.estado === 'fallido') return 'error'
  return result.estado === 'ejecutando' ? 'running' : 'pending'
}

function stateLabel(status: SourceItem['status']) {
  return { healthy: 'Saludable', partial: 'Parcial', error: 'Fallida', running: 'Ejecutando', pending: 'Sin ejecutar', disabled: 'Deshabilitada' }[status]
}

export default function LiveSourcesScreen({ data }: { data: ClientData }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const closeDetail = useCallback(() => setDetailOpen(false), [])
  const results = useMemo(() => new Map(data.sourceResults.map((result) => [result.fuente_id, result])), [data.sourceResults])
  const items = useMemo<SourceItem[]>(() => scanSources(data).map((source) => {
    const result = results.get(source.id) ?? null
    return { source, result, status: state(result) }
  }), [data, results])
  const selected = items.find((item) => item.source.id === selectedId) ?? items.find((item) => item.status === 'error' || item.status === 'partial') ?? items[0] ?? null
  const healthy = items.filter((item) => item.status === 'healthy').length
  const issues = items.filter((item) => item.status === 'error' || item.status === 'partial').length
  const enabledItems = items.filter((item) => item.status !== 'disabled')
  const activeResults = enabledItems.flatMap((item) => item.result ? [item.result] : [])
  const coverage = enabledItems.length && activeResults.length ? Math.round(healthy / enabledItems.length * 100) : null
  const observations = activeResults.reduce((sum, result) => sum + result.observaciones_generadas, 0)
  const normalized = activeResults.reduce((sum, result) => sum + result.observaciones_nuevas, 0)
  const duplicated = activeResults.reduce((sum, result) => sum + result.observaciones_duplicadas, 0)
  const newAssets = activeResults.reduce((sum, result) => sum + result.activos_nuevos, 0)
  const existingAssets = activeResults.reduce((sum, result) => sum + result.activos_existentes, 0)
  const visible = items.filter((item) => {
    const searchMatches = `${item.source.nombre} ${item.source.tipo_acceso} ${modules[item.source.nombre] ?? ''}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())
    return searchMatches && (filter === 'all' || (filter === 'healthy' ? item.status === 'healthy' : item.status === 'error' || item.status === 'partial'))
  })
  return <div className="sources-screen live-sources-screen">
    <div className="source-kpis" aria-label="Resumen de fuentes">
      {[
        { label: 'CONECTADAS', value: enabledItems.length, detail: 'Fuentes habilitadas', tone: '' },
        { label: 'SALUDABLES', value: healthy, detail: 'Finalizaron sin incidencias', tone: 'healthy' },
        { label: 'CON INCIDENCIAS', value: issues, detail: 'Fallaron o terminaron parcialmente', tone: 'partial' },
        { label: 'COBERTURA', value: coverage === null ? '—' : `${coverage}%`, detail: 'Fuentes completadas', tone: 'coverage' },
      ].map((metric) => <article className={`content-card source-kpi ${metric.tone ? `tone-${metric.tone}` : ''}`} key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small></article>)}
    </div>
    <div className="sources-workspace">
      <section className="content-card source-inventory" aria-labelledby="live-source-inventory-heading">
        <div className="source-inventory-header"><div className="portal-info-heading"><h2 id="live-source-inventory-heading">Herramientas integradas</h2><InfoTip label="herramientas integradas" text="Los proveedores y módulos internos se muestran dentro de cada herramienta." /></div><label className="source-search"><Search size={18} aria-hidden="true" /><span className="sr-only">Buscar fuente o módulo</span><input type="search" placeholder="Buscar fuente o módulo" value={query} onChange={(event) => setQuery(event.target.value)} />{query && <button type="button" aria-label="Limpiar búsqueda" onClick={() => setQuery('')}><X size={16} /></button>}</label></div>
        <div className="source-filters" role="group" aria-label="Filtrar fuentes">{[
          { id: 'all' as Filter, label: 'Todas', count: items.length },
          { id: 'healthy' as Filter, label: 'Saludables', count: healthy },
          { id: 'issues' as Filter, label: 'Con incidencias', count: issues },
        ].map((option) => <button key={option.id} type="button" className={filter === option.id ? 'active' : ''} aria-pressed={filter === option.id} onClick={() => setFilter(option.id)}>{option.label}<span>{option.count}</span></button>)}</div>
        <div className="source-records-scroller"><div className="source-record-head"><span>FUENTE</span><span>CONTRIBUCIÓN</span><span>RENDIMIENTO</span><span>ESTADO</span></div><div className="source-records">{visible.length ? visible.map((item) => <button type="button" className={`source-record${selected?.source.id === item.source.id ? ' selected' : ''}`} aria-pressed={selected?.source.id === item.source.id} aria-label={`Ver registro de ${item.source.nombre}`} key={item.source.id} onClick={() => { setSelectedId(item.source.id); setDetailOpen(true) }}><span className="source-identity"><span className={`source-monogram ${item.status}`}>{item.source.nombre.replace(/[^a-z]/gi, '').slice(0, 2).toUpperCase()}</span><span><strong>{item.source.nombre}</strong><small>{modules[item.source.nombre] ?? item.source.tipo_acceso}</small></span></span><span className="source-record-cell"><strong>{item.status === 'disabled' ? 'No evaluada' : item.result ? `${item.result.observaciones_generadas} observaciones` : 'Sin resultados'}</strong><small title={item.result?.error ?? undefined}>{item.result?.error ? sourceIssueSummary(item.result.error) : item.status === 'disabled' ? 'Fuera del flujo actual' : item.result ? `${item.result.activos_nuevos} activos nuevos` : 'Aún no consultada'}</small></span><span className="source-record-cell"><strong>{duration(item.result)}</strong><small>{dateTime(item.result?.finalizado_en)}</small></span><span className={`source-status ${item.status}`}>{stateLabel(item.status)}</span></button>) : <div className="source-empty">No hay fuentes que coincidan con la búsqueda y el filtro.</div>}</div></div>
      </section>
      <aside className="sources-side" aria-label="Calidad y cobertura de fuentes">
        <section className="content-card source-quality" aria-labelledby="live-source-quality-heading"><span className="source-panel-label" id="live-source-quality-heading">LECTURA DE CALIDAD</span>{selected ? <><span className={`source-quality-badge ${selected.status}`}>{stateLabel(selected.status).toUpperCase()}</span><h2>{selected.source.nombre}</h2><p>{selected.result?.error ? `${selected.result.error.slice(0, 220)}${selected.result.error.length > 220 ? '…' : ''}` : selected.result ? `Esta fuente terminó en estado «${selected.result.estado}» y generó ${selected.result.observaciones_generadas} observaciones.` : 'Esta fuente todavía no tiene resultados en el último análisis terminado.'}</p><div className="source-quality-facts"><div><span>Observaciones</span><strong>{selected.result?.observaciones_generadas ?? '—'}</strong></div><div><span>Activos nuevos</span><strong>{selected.result?.activos_nuevos ?? '—'}</strong></div><div><span>Duración</span><strong>{duration(selected.result)}</strong></div><div><span>Finalizó</span><strong>{dateTime(selected.result?.finalizado_en)}</strong></div></div><button type="button" className="source-detail-action" onClick={() => setDetailOpen(true)}>Ver registro de ejecución</button></> : <p className="source-quality-empty">No hay fuentes registradas.</p>}</section>
        <section className="content-card source-coverage" aria-labelledby="live-source-coverage-heading"><div className="source-card-heading"><h2 id="live-source-coverage-heading">CONTRIBUCIÓN POR FUENTE</h2><strong>{observations} obs.</strong></div>{observations > 0 ? <div className="source-coverage-bars">{items.map((item) => { const percent = Math.round((item.result?.observaciones_generadas ?? 0) / observations * 100); return <div className="source-coverage-row" key={item.source.id}><span>{item.source.nombre}</span><strong>{percent}%</strong><div className="source-coverage-track" role="img" aria-label={`${item.source.nombre}: ${percent}% de las observaciones`}><span style={{ width: `${percent}%` }} /></div></div> })}</div> : <p className="source-quality-empty">Aún no hay observaciones para calcular la contribución.</p>}</section>
        <section className="content-card source-normalization" aria-labelledby="live-source-normalization-heading"><div className="source-card-heading"><h2 id="live-source-normalization-heading">NORMALIZACIÓN</h2><strong>{newAssets} activos nuevos</strong></div><div className="source-normalization-facts"><div><span>Observaciones nuevas</span><strong>{normalized}</strong></div><div><span>Duplicadas</span><strong>{duplicated}</strong></div><div><span>Activos nuevos</span><strong>{newAssets}</strong></div><div><span>Activos existentes</span><strong>{existingAssets}</strong></div></div></section>
      </aside>
    </div>
    {detailOpen && selected && <LiveSourceLogDialog key={`${selected.source.id}-${selected.result?.id ?? 'none'}`} source={selected.source} result={selected.result} statusLabel={stateLabel(selected.status)} duration={duration(selected.result)} queries={data.risks.find(risk => risk.escaneo_id === data.latestFinishedScan?.id)?.cobertura?.infraestructura?.fuentes[selected.source.nombre]?.consultas ?? []} onClose={closeDetail} />}
  </div>
}
