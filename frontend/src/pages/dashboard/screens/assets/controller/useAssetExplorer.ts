import { useMemo, useState } from 'react'
import { mockAssets, type AssetFilter } from '../services/assetsMock'

const pageSize = 7

function normalize(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('es')
}

export function useAssetExplorer() {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<AssetFilter>('Todos')
  const [newOnly, setNewOnly] = useState(false)
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState(mockAssets[0].id)

  const searchedAssets = useMemo(() => {
    const search = normalize(query.trim())
    return mockAssets.filter((asset) =>
      (!newOnly || asset.isNew) &&
      (!search || normalize(`${asset.value} ${asset.detail} ${asset.kind} ${asset.sources.join(' ')}`).includes(search)),
    )
  }, [newOnly, query])

  const filterCounts = useMemo(() => {
    const counts: Record<AssetFilter, number> = { Todos: searchedAssets.length, Dominio: 0, Subdominio: 0, 'IP pública': 0, Correo: 0 }
    searchedAssets.forEach((asset) => { counts[asset.kind] += 1 })
    return counts
  }, [searchedAssets])

  const matchingAssets = useMemo(() => searchedAssets.filter((asset) => filter === 'Todos' || asset.kind === filter), [filter, searchedAssets])
  const pageCount = Math.max(1, Math.ceil(matchingAssets.length / pageSize))
  const currentPage = Math.min(page, pageCount - 1)
  const visibleAssets = matchingAssets.slice(currentPage * pageSize, (currentPage + 1) * pageSize)

  const selectedAsset = visibleAssets.find((asset) => asset.id === selectedId) ?? visibleAssets[0] ?? null

  return {
    query,
    setQuery: (value: string) => { setQuery(value); setPage(0); setSelectedId('') },
    filter,
    setFilter: (value: AssetFilter) => { setFilter(value); setPage(0); setSelectedId('') },
    newOnly,
    toggleNewOnly: () => { setNewOnly((current) => !current); setPage(0); setSelectedId('') },
    filterCounts,
    matchingCount: matchingAssets.length,
    page: currentPage,
    pageCount,
    pageStart: currentPage * pageSize + 1,
    pageEnd: currentPage * pageSize + visibleAssets.length,
    setPage: (value: number) => { setPage(value); setSelectedId('') },
    visibleAssets,
    selectedAsset,
    selectAsset: setSelectedId,
  }
}
