import { Search, X } from 'lucide-react'
import type { useFindingExplorer } from '../controller/useFindingExplorer'
import { findingFilters } from '../services/findingsMock'
import FindingRow from './FindingRow'

type Explorer = ReturnType<typeof useFindingExplorer>

export default function FindingQueue({ explorer }: { explorer: Explorer }) {
  return <section className="content-card finding-queue" aria-labelledby="finding-queue-heading">
    <div className="finding-queue-toolbar">
      <div><h2 id="finding-queue-heading">Cola de investigación</h2><p>{explorer.visibleFindings.length} {explorer.visibleFindings.length === 1 ? 'hallazgo visible' : 'hallazgos visibles'}</p></div>
      <label className="finding-search"><Search size={17} aria-hidden="true" /><span className="sr-only">Buscar hallazgo o activo</span><input type="search" value={explorer.query} onChange={(event) => explorer.changeQuery(event.target.value)} placeholder="Buscar hallazgo o activo" />{explorer.query && <button type="button" aria-label="Limpiar búsqueda" onClick={() => explorer.changeQuery('')}><X size={16} /></button>}</label>
    </div>
    <div className="finding-filters" role="group" aria-label="Filtrar por severidad">
      {findingFilters.map((option) => <button key={option.value} type="button" className={explorer.filter === option.value ? 'active' : ''} aria-pressed={explorer.filter === option.value} onClick={() => explorer.changeFilter(option.value)}>{option.label}<span>{explorer.filterCounts[option.value]}</span></button>)}
    </div>
    <div className="finding-record-head finding-grid" aria-hidden="true"><span>PRIORIDAD</span><span>HALLAZGO / ACTIVO</span><span>REGLA / EVIDENCIA</span><span>CONFIANZA</span><span>ESTADO</span></div>
    <div className="finding-record-list">{explorer.visibleFindings.length ? explorer.visibleFindings.map((finding) => <FindingRow key={finding.id} finding={finding} selected={explorer.selectedFinding?.id === finding.id} onSelect={() => explorer.selectFinding(finding.id)} />) : <p className="finding-empty">No hay hallazgos que coincidan con la búsqueda y el filtro.</p>}</div>
    {explorer.pageCount > 1 && <nav className="finding-pagination" aria-label="Páginas de hallazgos"><span>Página {explorer.page + 1} de {explorer.pageCount}</span><div><button type="button" disabled={explorer.page === 0} onClick={() => explorer.changePage(explorer.page - 1)}>Anterior</button><button type="button" disabled={explorer.page >= explorer.pageCount - 1} onClick={() => explorer.changePage(explorer.page + 1)}>Siguiente</button></div></nav>}
  </section>
}
