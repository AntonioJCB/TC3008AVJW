type CrtshReport = {
  version: 1
  entries: Record<string, unknown>[]
  queries: { query: string; status: string; entries: number; checked_at?: string; error?: string }[]
  covered_targets: string[]
}

type HarvesterReport = {
  items: { type: string; value: string; sources: string[]; targets?: string[] }[]
  runs: { target: string; source_executions: {
    source: string; status: string; result_count: number; stop_reason?: string | null; error_type?: string | null
  }[] }[]
}

export function isHarvesterReport(value: unknown): value is HarvesterReport {
  if (typeof value !== 'object' || value === null) return false
  const report = value as Partial<HarvesterReport>
  return Array.isArray(report.items) && Array.isArray(report.runs)
}

export function isCrtshReport(value: unknown): value is CrtshReport {
  if (typeof value !== 'object' || value === null) return false
  const report = value as Partial<CrtshReport>
  return report.version === 1 && Array.isArray(report.entries) && Array.isArray(report.queries)
}


export type SpiderFootReport = {
  profile: 'baxter-passive-v1'; module: string; provider: string; target: string
  status: string; query: string; results: number; error?: string; limitations: string[]
  checked_at: string; events: SpiderFootReportEvent[]
  header_evaluation?: { status: string; requested: number; complete: number; unverifiable: number; max_results: number; max_age_days: number }
  redirect_evaluation?: { status: string; requested: number; complete: number; unverifiable: number; max_results: number; max_age_days: number }
  checks?: DnsPostureCheck[]
  unique_urls?: number
  registrable_domain?: string; is_subdomain?: boolean; registration_state?: string
  field_states?: Record<string, string>
  registrar?: { name?: string | null; handle?: string | null }
  dates?: Record<string, string>; statuses?: string[]; nameservers?: string[]
  references?: { href: string; rel?: string | null; type?: string | null }[]
}

export type SpiderFootReportEvent = {
  event_type: string; data: string; source_data: string
  observed_at?: string | null
  metadata?: Record<string, unknown>
}

export type DnsPostureCheck = {
  check: string; name: string; rrtype: string
  state: 'present' | 'absent' | 'error' | 'unverified' | 'not_applicable'
  records: { name: string; type: string; ttl?: number; data: string }[]
  dnssec_validated: boolean | null; rcode: number | null; checked_at: string
  query: string; interpretation: string
  issues: { code: string; message: string; severity: string; evaluable: boolean; rule?: string | null }[]
  cname_target_assessment?: {
    target: string | null; state: 'resolvable' | 'exists_without_address' | 'nxdomain' | 'unverified'
    checked_at: string; passive: true; claimability_verified: false; attributed_to_customer: false
    queries: { rrtype: string; state: string; rcode: number | null; http_status?: number; query: string }[]
    interpretation: string
  }
}

function isDnsPostureCheck(value: unknown): value is DnsPostureCheck {
  if (!value || typeof value !== 'object') return false
  const check = value as Partial<DnsPostureCheck>
  return typeof check.check === 'string' && typeof check.name === 'string' && typeof check.rrtype === 'string'
    && ['present', 'absent', 'error', 'unverified', 'not_applicable'].includes(check.state || '')
    && typeof check.interpretation === 'string' && Array.isArray(check.records) && Array.isArray(check.issues)
    && check.records.every(record => record && typeof record.name === 'string' && typeof record.type === 'string' && typeof record.data === 'string')
    && check.issues.every(issue => issue && typeof issue.code === 'string' && typeof issue.message === 'string' && typeof issue.evaluable === 'boolean')
    && (check.cname_target_assessment === undefined
      || (typeof check.cname_target_assessment === 'object'
        && typeof check.cname_target_assessment.state === 'string'
        && typeof check.cname_target_assessment.interpretation === 'string'
        && Array.isArray(check.cname_target_assessment.queries)))
}

export function getSpiderFootReports(value: unknown): SpiderFootReport[] {
  if (!Array.isArray(value)) return []
  const modules: Record<string, string> = { sfp_baxter_dns_doh: 'google_dns_doh', sfp_baxter_urlscan: 'urlscan', sfp_baxter_commoncrawl: 'common_crawl', sfp_baxter_rdap: 'rdap', sfp_baxter_internetdb: 'internetdb', sfp_baxter_shodan: 'shodan' }
  const result: SpiderFootReport[] = []
  type ChunkGroup = {
    summary?: SpiderFootReport & { check_count?: number; event_count?: number }
    checks: DnsPostureCheck[]
    fragments: Map<number, Map<number, { count: number; text: string }>>
    reportFragments: Map<number, { count: number; text: string }>
    fragmentMeta?: SpiderFootReport
  }
  const chunks = new Map<string, ChunkGroup>()
  value.forEach((row: unknown) => {
    if (!row || typeof row !== 'object') return []
    const event = row as Record<string, unknown>
    if (typeof event.module !== 'string' || !modules[event.module] || event.event_type !== 'RAW_RIR_DATA' || typeof event.data !== 'string' || ['1', 'true'].includes(String(event.false_positive).trim().toLowerCase())) return []
    try {
      const report = JSON.parse(event.data) as (Partial<SpiderFootReport> & {
        chunk_type?: string; check?: unknown; check_count?: number; event_count?: number
        event_index?: number; fragment_index?: number; fragment_count?: number; event_fragment?: string
        report_fragment?: string
      }) | null
      if (!report || report.profile !== 'baxter-passive-v1' || report.provider !== modules[event.module] || report.target !== event.scan_target || typeof report.target !== 'string' || typeof report.query !== 'string' || typeof report.results !== 'number' || typeof report.checked_at !== 'string' || !['ok', 'empty', 'partial', 'error', 'unavailable'].includes(report.status || '') || !Array.isArray(report.events) || !Array.isArray(report.limitations)) return []
      if (report.error !== undefined && typeof report.error !== 'string') return []
      if (!report.limitations.every(item => typeof item === 'string') || !report.events.every(item => item && typeof item.event_type === 'string' && typeof item.data === 'string' && typeof item.source_data === 'string')) return []
      if (report.checks !== undefined && (!Array.isArray(report.checks) || !report.checks.every(isDnsPostureCheck))) return []
      if (['summary', 'dns_check', 'provider_event', 'report_fragment'].includes(report.chunk_type || '')) {
        const key = `${event.module}\u0000${report.target}\u0000${report.checked_at}`
        const group: ChunkGroup = chunks.get(key) ?? { checks: [], fragments: new Map(), reportFragments: new Map() }
        if (report.chunk_type === 'summary' && !group.summary) group.summary = { ...report, module: event.module } as SpiderFootReport & { check_count?: number; event_count?: number }
        if (report.chunk_type === 'dns_check' && isDnsPostureCheck(report.check)) group.checks.push(report.check)
        if (report.chunk_type === 'provider_event' && typeof report.event_index === 'number'
          && typeof report.fragment_index === 'number' && typeof report.fragment_count === 'number'
          && typeof report.event_fragment === 'string') {
          const parts = group.fragments.get(report.event_index) ?? new Map()
          parts.set(report.fragment_index, { count: report.fragment_count, text: report.event_fragment })
          group.fragments.set(report.event_index, parts)
        }
        if (report.chunk_type === 'report_fragment' && typeof report.fragment_index === 'number'
          && typeof report.fragment_count === 'number' && typeof report.report_fragment === 'string') {
          group.fragmentMeta = group.fragmentMeta ?? ({ ...report, module: event.module } as SpiderFootReport)
          group.reportFragments.set(report.fragment_index, { count: report.fragment_count, text: report.report_fragment })
        }
        chunks.set(key, group)
      } else {
        result.push({ ...report, module: event.module } as SpiderFootReport)
      }
    } catch { return [] }
  })
  chunks.forEach(group => {
    if (group.reportFragments.size) {
      const count = group.reportFragments.values().next().value?.count ?? 0
      const complete = group.reportFragments.size === count
        && [...Array(count).keys()].every(index => group.reportFragments.has(index))
      if (complete && group.fragmentMeta) {
        try {
          const parsed = JSON.parse([...Array(count).keys()]
            .map(index => group.reportFragments.get(index)?.text || '').join('')) as SpiderFootReport
          if (parsed.profile === 'baxter-passive-v1' && parsed.provider === group.fragmentMeta.provider
            && parsed.target === group.fragmentMeta.target && typeof parsed.query === 'string'
            && typeof parsed.results === 'number' && typeof parsed.checked_at === 'string'
            && ['ok', 'empty', 'partial', 'error', 'unavailable'].includes(parsed.status)
            && Array.isArray(parsed.events) && Array.isArray(parsed.limitations)
            && parsed.events.every(item => item && typeof item.event_type === 'string'
              && typeof item.data === 'string' && typeof item.source_data === 'string')
            && (parsed.checks === undefined || parsed.checks.every(isDnsPostureCheck))) {
            result.push({ ...parsed, module: group.fragmentMeta.module })
            return
          }
        } catch { /* handled as an incomplete report below */ }
      }
      if (group.fragmentMeta) result.push({
        ...group.fragmentMeta,
        status: 'partial', events: [], checks: [], results: 0,
        error: `Solo se recuperaron ${group.reportFragments.size} de ${count} fragmentos del reporte.`,
      })
      return
    }
    if (!group.summary) return
    const events: SpiderFootReportEvent[] = group.checks.map(check => ({ event_type: 'DNS_POSTURE', data: `${check.check}:${check.state}`, source_data: group.summary!.target }))
    group.fragments.forEach((parts) => {
      const count = parts.values().next().value?.count ?? 0
      if (parts.size !== count || [...Array(count).keys()].some(index => !parts.has(index))) return
      try {
        const parsed = JSON.parse([...Array(count).keys()].map(index => parts.get(index)?.text || '').join('')) as SpiderFootReportEvent
        if (parsed && typeof parsed.event_type === 'string' && typeof parsed.data === 'string' && typeof parsed.source_data === 'string') events.push(parsed)
      } catch { return }
    })
    const expectedChecks = group.summary.check_count
    const expectedEvents = group.summary.event_count
    const incompleteChecks = typeof expectedChecks === 'number' && expectedChecks !== group.checks.length
    const incompleteEvents = typeof expectedEvents === 'number' && expectedEvents !== events.length
    const incomplete = incompleteChecks || incompleteEvents
    const error = incompleteChecks ? `Solo se recuperaron ${group.checks.length} de ${expectedChecks} comprobaciones DNS.`
      : incompleteEvents ? `Solo se recuperaron ${events.length} de ${expectedEvents} evidencias del proveedor.` : group.summary.error
    result.push({
      ...group.summary,
      status: incomplete ? 'partial' : group.summary.status,
      error,
      checks: group.checks,
      events,
    })
  })
  return result
}

export type SpiderFootDnsModuleReport = {
  module: string
  target: string
  events: Record<string, number>
}

export function getSpiderFootDnsModules(value: unknown): SpiderFootDnsModuleReport[] {
  if (!Array.isArray(value)) return []
  const allowed = new Set(['sfp_dnsresolve', 'sfp_dnsraw', 'sfp_robtex', 'sfp_crobat_api'])
  const grouped = new Map<string, SpiderFootDnsModuleReport>()
  value.forEach((row: unknown) => {
    if (!row || typeof row !== 'object') return
    const event = row as Record<string, unknown>
    if (typeof event.module !== 'string' || !allowed.has(event.module)
      || typeof event.event_type !== 'string' || typeof event.scan_target !== 'string'
      || ['1', 'true'].includes(String(event.false_positive).trim().toLowerCase())) return
    if (typeof event.source_data === 'string'
      && /"profile"\s*:\s*"baxter-passive-v1"/.test(event.source_data)) return
    const key = `${event.module}\u0000${event.scan_target}`
    const current = grouped.get(key) ?? { module: event.module, target: event.scan_target, events: {} }
    current.events[event.event_type] = (current.events[event.event_type] || 0) + 1
    grouped.set(key, current)
  })
  return [...grouped.values()]
}
