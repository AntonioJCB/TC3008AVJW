import { useCallback, useMemo, useState } from 'react'
import AssetDetailDialog from './components/AssetDetailDialog'
import AssetInsights from './components/AssetInsights'
import AssetInventory from './components/AssetInventory'
import AssetKpis from './components/AssetKpis'
import { useAssetExplorer } from './controller/useAssetExplorer'
import { mockAssets } from './services/assetsMock'
import type { ClientData } from '../../services/clientData'
import { liveAssets } from '../../services/liveAdapters'
import './assets.css'

export default function AssetsScreen({ data }: { data?: ClientData }) {
  const records = useMemo(() => data ? liveAssets(data) : mockAssets, [data])
  const explorer = useAssetExplorer(records)
  const [detailOpen, setDetailOpen] = useState(false)
  const closeDetail = useCallback(() => setDetailOpen(false), [])
  const completed = data?.sourceResults.filter((result) => result.estado === 'completado').length ?? 0
  const quality = data ? {
    coverage: data.sources.length ? Math.round(completed / data.sources.length * 100) : 0,
    completed,
    sources: data.sources.length,
    raw: data.sourceResults.reduce((total, result) => total + result.observaciones_generadas, 0),
    normalized: data.sourceResults.reduce((total, result) => total + result.observaciones_nuevas, 0),
    duplicates: data.sourceResults.reduce((total, result) => total + result.observaciones_duplicadas, 0),
    assets: data.assetCount,
  } : undefined
  const newCount = records.filter((asset) => asset.isNew).length
  const kpis = data ? [
    { label: 'TOTAL', value: data.assetCount, detail: 'Activos registrados', tone: 'total' },
    { label: 'SUBDOMINIOS', value: records.filter((asset) => asset.kind === 'Subdominio').length, detail: 'En el inventario visible', tone: 'subdomains' },
    { label: 'IPS PÚBLICAS', value: records.filter((asset) => asset.kind === 'IP pública').length, detail: 'En el inventario visible', tone: 'ips' },
    { label: 'NUEVOS', value: newCount, detail: 'Desde el último análisis', tone: 'new' },
  ] : undefined

  return (
    <div className="assets-screen">
      <h2 className="sr-only">Activos</h2>
      <AssetKpis values={kpis} />
      <div className="assets-workspace">
        <AssetInventory assets={explorer.visibleAssets} selectedId={explorer.selectedAsset?.id ?? null} onSelect={explorer.selectAsset} query={explorer.query} onQueryChange={explorer.setQuery} filter={explorer.filter} filterCounts={explorer.filterCounts} onFilterChange={explorer.setFilter} newOnly={explorer.newOnly} onToggleNew={explorer.toggleNewOnly} matchingCount={explorer.matchingCount} page={explorer.page} pageCount={explorer.pageCount} pageStart={explorer.pageStart} pageEnd={explorer.pageEnd} onPageChange={explorer.setPage} />
        <AssetInsights asset={explorer.selectedAsset} onOpenDetail={() => setDetailOpen(true)} quality={quality} />
      </div>
      {detailOpen && explorer.selectedAsset && <AssetDetailDialog asset={explorer.selectedAsset} onClose={closeDetail} live={Boolean(data)} />}
    </div>
  )
}
