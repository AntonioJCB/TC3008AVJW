import { useMemo, useState } from 'react'
import { mockSources, type SourceFilter } from '../services/sourcesMock'

function normalize(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('es')
}

export function useSourceExplorer() {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<SourceFilter>('all')
  const [selectedId, setSelectedId] = useState('shodan')

  const searchedSources = useMemo(() => {
    const term = normalize(query.trim())
    return mockSources.filter((source) => !term || normalize(`${source.name} ${source.type} ${source.purpose}`).includes(term))
  }, [query])

  const filterCounts = useMemo(() => ({
    all: searchedSources.length,
    healthy: searchedSources.filter((source) => source.status === 'healthy').length,
    partial: searchedSources.filter((source) => source.status === 'partial').length,
  }), [searchedSources])

  const visibleSources = useMemo(() => searchedSources.filter((source) => filter === 'all' || source.status === filter), [filter, searchedSources])
  const selectedSource = visibleSources.find((source) => source.id === selectedId) ?? visibleSources[0] ?? null

  return { query, setQuery, filter, setFilter, filterCounts, visibleSources, selectedSource, selectSource: setSelectedId }
}
