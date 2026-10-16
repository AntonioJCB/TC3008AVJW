import { useMemo, useState } from 'react'
import { demoProject, type AssetKind } from '../../services/demoData'

export function useAssetFilters() {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<AssetKind | 'Todos'>('Todos')
  const assets = useMemo(() => demoProject.assets.filter((asset) =>
    (kind === 'Todos' || asset.kind === kind) &&
    `${asset.value} ${asset.detail}`.toLowerCase().includes(query.trim().toLowerCase()),
  ), [kind, query])
  return { assets, query, setQuery, kind, setKind }
}
