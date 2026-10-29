import { useMemo, useState } from 'react'
import { historyEvents, type HistoryFilter, type HistoryRange } from '../services/historyMock'

export const historyPageSize = 8

function normalize(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('es')
}

export function useHistoryExplorer() {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<HistoryFilter>('all')
  const [range, setRange] = useState<HistoryRange>('30D')
  const [page, setPage] = useState(0)

  const searchedEvents = useMemo(() => {
    const term = normalize(query.trim())
    return historyEvents.filter((event) => !term || normalize(`${event.title} ${event.detail} ${event.context} ${event.contextDetail} ${event.status}`).includes(term))
  }, [query])

  const filterCounts = useMemo(() => ({
    all: searchedEvents.length,
    asset: searchedEvents.filter((event) => event.kind === 'asset').length,
    finding: searchedEvents.filter((event) => event.kind === 'finding').length,
    source: searchedEvents.filter((event) => event.kind === 'source').length,
    scan: searchedEvents.filter((event) => event.kind === 'scan').length,
  }), [searchedEvents])

  const matchingEvents = useMemo(() => searchedEvents.filter((event) => filter === 'all' || event.kind === filter), [filter, searchedEvents])
  const pageCount = Math.max(1, Math.ceil(matchingEvents.length / historyPageSize))
  const visibleEvents = matchingEvents.slice(page * historyPageSize, (page + 1) * historyPageSize)

  function changeQuery(value: string) { setQuery(value); setPage(0) }
  function changeFilter(value: HistoryFilter) { setFilter(value); setPage(0) }

  return {
    query, changeQuery, filter, changeFilter, filterCounts, range, setRange,
    visibleEvents, page, pageCount, changePage: setPage,
  }
}
