import { Search, X } from 'lucide-react'
import SourceRow from './SourceRow'
import type { SourceFilter, SourceRecord } from '../services/sourcesMock'

interface Props {
  query: string
  setQuery: (value: string) => void
  filter: SourceFilter
  setFilter: (value: SourceFilter) => void
  filterCounts: Record<SourceFilter, number>
  visibleSources: SourceRecord[]
  selectedSource: SourceRecord | null
  selectSource: (id: string) => void
}

const filters: { id: SourceFilter; label: string }[] = [
  { id: 'all', label: 'Todas' },
  { id: 'healthy', label: 'Saludables' },
  { id: 'partial', label: 'Parciales' },
]

export default function SourceInventory({ query, setQuery, filter, setFilter, filterCounts, visibleSources, selectedSource, selectSource }: Props) {
  return <section className="content-card source-inventory" aria-labelledby="source-inventory-heading">
    <div className="source-inventory-header">
      <div><h2 id="source-inventory-heading">Inventario de fuentes</h2><p>{visibleSources.length} {visibleSources.length === 1 ? 'fuente visible' : 'fuentes visibles'}</p></div>
      <label className="source-search"><Search size={18} aria-hidden="true" /><span className="sr-only">Buscar fuente</span><input type="search" placeholder="Buscar fuente o tipo de dato" value={query} onChange={(event) => setQuery(event.target.value)} />{query && <button type="button" aria-label="Limpiar búsqueda" onClick={() => setQuery('')}><X size={16} /></button>}</label>
    </div>
    <div className="source-filters" role="group" aria-label="Filtrar por salud">
      {filters.map((option) => <button key={option.id} type="button" className={filter === option.id ? 'active' : ''} aria-pressed={filter === option.id} onClick={() => setFilter(option.id)}>{option.label}<span>{filterCounts[option.id]}</span></button>)}
    </div>
    <div className="source-records-scroller">
      <div className="source-record-head"><span>FUENTE</span><span>CONTRIBUCIÓN</span><span>RENDIMIENTO</span><span>ESTADO</span></div>
      <div className="source-records">{visibleSources.length ? visibleSources.map((source) => <SourceRow key={source.id} source={source} selected={selectedSource?.id === source.id} onSelect={() => selectSource(source.id)} />) : <div className="source-empty">No hay fuentes que coincidan con la búsqueda y el filtro.</div>}</div>
    </div>
  </section>
}
