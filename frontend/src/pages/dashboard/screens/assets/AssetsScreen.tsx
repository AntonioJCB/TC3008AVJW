import { Search } from 'lucide-react'
import { type AssetKind } from '../../services/demoData'
import AssetRow from './components/AssetRow'
import { useAssetFilters } from './useAssetFilters'

const kinds: Array<AssetKind | 'Todos'> = ['Todos', 'Subdominio', 'IP pública', 'Correo', 'Puerto']

export default function AssetsScreen() {
  const { assets, query, setQuery, kind, setKind } = useAssetFilters()
  return (
    <section className="content-card asset-section" aria-labelledby="assets-title">
      <div className="section-heading"><div><div className="eyebrow">INVENTARIO</div><h2 id="assets-title">Activos descubiertos</h2><p>Registros ficticios del dominio de muestra.</p></div><span className="count-pill">{assets.length} {assets.length === 1 ? 'resultado' : 'resultados'}</span></div>
      <div className="filter-row">
        <label className="search-box"><Search size={17} /><span className="sr-only">Buscar activos</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar por nombre o detalle" /></label>
        <label className="select-box"><span className="sr-only">Tipo de activo</span><select value={kind} onChange={(event) => setKind(event.target.value as AssetKind | 'Todos')}>{kinds.map((item) => <option key={item}>{item}</option>)}</select></label>
      </div>
      <div className="asset-list">{assets.length ? assets.map((asset) => <AssetRow asset={asset} key={asset.id} />) : <div className="empty-result">No hay activos que coincidan con los filtros.</div>}</div>
    </section>
  )
}
