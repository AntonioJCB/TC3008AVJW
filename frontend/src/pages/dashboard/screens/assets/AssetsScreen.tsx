import { useCallback, useState } from 'react'
import AssetDetailDialog from './components/AssetDetailDialog'
import AssetInsights from './components/AssetInsights'
import AssetInventory from './components/AssetInventory'
import AssetKpis from './components/AssetKpis'
import { useAssetExplorer } from './controller/useAssetExplorer'
import './assets.css'

export default function AssetsScreen() {
  const explorer = useAssetExplorer()
  const [detailOpen, setDetailOpen] = useState(false)
  const closeDetail = useCallback(() => setDetailOpen(false), [])

  return (
    <div className="assets-screen">
      <h2 className="sr-only">Activos</h2>
      <AssetKpis />
      <div className="assets-workspace">
        <AssetInventory assets={explorer.visibleAssets} selectedId={explorer.selectedAsset?.id ?? null} onSelect={explorer.selectAsset} query={explorer.query} onQueryChange={explorer.setQuery} filter={explorer.filter} filterCounts={explorer.filterCounts} onFilterChange={explorer.setFilter} newOnly={explorer.newOnly} onToggleNew={explorer.toggleNewOnly} matchingCount={explorer.matchingCount} page={explorer.page} pageCount={explorer.pageCount} pageStart={explorer.pageStart} pageEnd={explorer.pageEnd} onPageChange={explorer.setPage} />
        <AssetInsights asset={explorer.selectedAsset} onOpenDetail={() => setDetailOpen(true)} />
      </div>
      {detailOpen && explorer.selectedAsset && <AssetDetailDialog asset={explorer.selectedAsset} onClose={closeDetail} />}
    </div>
  )
}
