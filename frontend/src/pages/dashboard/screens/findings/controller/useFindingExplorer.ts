import { useMemo, useState } from 'react'
import { mockFindings, type FindingFilter } from '../services/findingsMock'

export const findingPageSize = 6

function normalize(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('es')
}

export function useFindingExplorer() {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<FindingFilter>('all')
  const [selectedId, setSelectedId] = useState(mockFindings[0].id)
  const [page, setPage] = useState(0)

  const searchedFindings = useMemo(() => {
    const term = normalize(query.trim())
    return mockFindings.filter((finding) => !term || normalize(`${finding.title} ${finding.asset} ${finding.rule} ${finding.sources.join(' ')}`).includes(term))
  }, [query])

  const filterCounts = useMemo(() => ({
    all: searchedFindings.length,
    critical: searchedFindings.filter((finding) => finding.severity === 'critical').length,
    high: searchedFindings.filter((finding) => finding.severity === 'high').length,
    medium: searchedFindings.filter((finding) => finding.severity === 'medium').length,
    low: searchedFindings.filter((finding) => finding.severity === 'low').length,
  }), [searchedFindings])

  const matchingFindings = useMemo(() => searchedFindings.filter((finding) => filter === 'all' || finding.severity === filter), [filter, searchedFindings])
  const pageCount = Math.max(1, Math.ceil(matchingFindings.length / findingPageSize))
  const visibleFindings = matchingFindings.slice(page * findingPageSize, (page + 1) * findingPageSize)
  const selectedFinding = visibleFindings.find((finding) => finding.id === selectedId) ?? visibleFindings[0] ?? null
  const selectedPriority = selectedFinding ? mockFindings.findIndex((finding) => finding.id === selectedFinding.id) + 1 : 0

  function changeQuery(value: string) { setQuery(value); setPage(0) }
  function changeFilter(value: FindingFilter) { setFilter(value); setPage(0) }

  return {
    query, changeQuery, filter, changeFilter, filterCounts,
    visibleFindings, selectedFinding, selectedPriority, selectFinding: setSelectedId,
    page, pageCount, changePage: setPage,
  }
}
