import { Search, X } from 'lucide-react'
import type { useHistoryExplorer } from '../controller/useHistoryExplorer'
import { historyFilters, type HistoryEvent } from '../services/historyMock'
import HistoryRow from './HistoryRow'

type Explorer = ReturnType<typeof useHistoryExplorer>

export default function HistoryLog({ explorer, onOpenEvent }: { explorer: Explorer; onOpenEvent: (event: HistoryEvent) => void }) {
  return <section className="content-card history-log-card" aria-labelledby="history-log-title">
    <div className="history-log-toolbar">
      <div><h2 id="history-log-title">Registro de cambios</h2><p>{explorer.visibleEvents.length} {explorer.visibleEvents.length === 1 ? 'cambio visible' : 'cambios visibles'}</p></div>
      <label className="history-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Buscar cambio, activo o fuente</span><input type="search" placeholder="Buscar cambio, activo o fuente" value={explorer.query} onChange={(event) => explorer.changeQuery(event.target.value)} />{explorer.query && <button type="button" aria-label="Limpiar búsqueda" onClick={() => explorer.changeQuery('')}><X size={16} /></button>}</label>
    </div>
    <div className="history-filters" role="group" aria-label="Filtrar cambios históricos">
      {historyFilters.map((option) => <button key={option.kind} type="button" aria-pressed={explorer.filter === option.kind} className={explorer.filter === option.kind ? 'active' : ''} onClick={() => explorer.changeFilter(option.kind)}>{option.label}<span>{explorer.filterCounts[option.kind]}</span></button>)}
    </div>
    <div className="history-log-head history-log-grid" aria-hidden="true"><span>FECHA</span><span>CAMBIO</span><span>CONTEXTO</span><span>IMPACTO</span><span>ESTADO</span></div>
    <div className="history-entries">{explorer.visibleEvents.length ? explorer.visibleEvents.map((event) => <HistoryRow key={event.id} event={event} onOpen={() => onOpenEvent(event)} />) : <p className="history-empty">No hay cambios que coincidan con la búsqueda y el filtro.</p>}</div>
    {explorer.pageCount > 1 && <nav className="history-pagination" aria-label="Páginas del historial"><span>Página {explorer.page + 1} de {explorer.pageCount}</span><div><button type="button" disabled={explorer.page === 0} onClick={() => explorer.changePage(explorer.page - 1)}>Anterior</button><button type="button" disabled={explorer.page >= explorer.pageCount - 1} onClick={() => explorer.changePage(explorer.page + 1)}>Siguiente</button></div></nav>}
  </section>
}
