import { Search, X } from 'lucide-react'
import AssetRow from './AssetRow'
import { assetFilters, type AssetFilter, type AssetRecord } from '../services/assetsMock'

interface AssetInventoryProps {
  assets: AssetRecord[]
  selectedId: string | null
  onSelect: (id: string) => void
  query: string
  onQueryChange: (value: string) => void
  filter: AssetFilter
  filterCounts: Record<AssetFilter, number>
  onFilterChange: (value: AssetFilter) => void
  newOnly: boolean
  onToggleNew: () => void
  matchingCount: number
  page: number
  pageCount: number
  pageStart: number
  pageEnd: number
  onPageChange: (page: number) => void
}

export default function AssetInventory({ assets, selectedId, onSelect, query, onQueryChange, filter, filterCounts, onFilterChange, newOnly, onToggleNew, matchingCount, page, pageCount, pageStart, pageEnd, onPageChange }: AssetInventoryProps) {
  return (
    <section className="content-card asset-inventory" aria-labelledby="inventory-heading">
      <div className="asset-inventory-header">
        <div><h3 id="inventory-heading">Inventario normalizado</h3><p>{pageCount > 1 ? `${pageStart}–${pageEnd} de ${matchingCount} activos` : `${matchingCount} ${matchingCount === 1 ? 'activo visible' : 'activos visibles'}`}</p></div>
        <div className="asset-inventory-actions">
          <label className="asset-search"><Search size={18} aria-hidden="true" /><span className="sr-only">Buscar activos</span><input type="search" value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Buscar dominio, IP o correo" />{query && <button type="button" onClick={() => onQueryChange('')} aria-label="Limpiar búsqueda"><X size={16} /></button>}</label>
          <button className="asset-new-filter" type="button" aria-pressed={newOnly} onClick={onToggleNew}>{newOnly ? 'Mostrar todos' : 'Mostrar nuevos'}</button>
        </div>
      </div>
      <div className="asset-filter-tabs" role="group" aria-label="Filtrar por tipo de activo">
        {assetFilters.map((option) => <button type="button" key={option.kind} className={filter === option.kind ? 'active' : ''} aria-pressed={filter === option.kind} onClick={() => onFilterChange(option.kind)}>{option.label}<span>{filterCounts[option.kind]}</span></button>)}
      </div>
      <div className="asset-table-scroll">
        <table className="asset-table">
          <thead><tr><th>TIPO</th><th>ACTIVO</th><th>EXPOSICIÓN</th><th>FUENTES</th><th>ÚLTIMA OBSERVACIÓN</th></tr></thead>
          <tbody>{assets.length ? assets.map((asset) => <AssetRow key={asset.id} asset={asset} selected={asset.id === selectedId} onSelect={() => onSelect(asset.id)} />) : <tr><td colSpan={5} className="asset-empty">No hay activos que coincidan con los filtros.</td></tr>}</tbody>
        </table>
      </div>
      {pageCount > 1 && <nav className="asset-pagination" aria-label="Páginas del inventario">
        <span>Página {page + 1} de {pageCount}</span>
        <div><button type="button" disabled={page === 0} onClick={() => onPageChange(page - 1)}>Anterior</button><button type="button" disabled={page === pageCount - 1} onClick={() => onPageChange(page + 1)}>Siguiente</button></div>
      </nav>}
    </section>
  )
}
