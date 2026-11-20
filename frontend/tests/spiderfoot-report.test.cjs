const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')

function load(relative, dependencies = {}) {
  const code = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/pages/dashboard', relative), 'utf8'), {
    compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const exports = {}
  vm.runInNewContext(code, { exports, require: name => dependencies[name] || require(name) })
  return exports
}
const helpers = load('services/sourceReports.ts')
const Component = load('components/SpiderFootEvidence.tsx', { '../services/sourceReports': helpers }).default
function raw(status, more = {}) {
  return [{ module: 'sfp_baxter_urlscan', event_type: 'RAW_RIR_DATA', scan_target: 'api.example.com', data: JSON.stringify({
    profile: 'baxter-passive-v1', provider: 'urlscan', target: 'api.example.com', status, query: 'https://urlscan.io/api/v1/search/',
    results: 0, checked_at: '2026-11-18T00:00:00Z', limitations: [], events: [], ...more,
  }) }]
}
function render(value, target) { return renderToStaticMarkup(React.createElement(Component, { raw: value, target })) }
function dnsRaw() {
  return [{ module: 'sfp_baxter_dns_doh', event_type: 'RAW_RIR_DATA', scan_target: 'api.example.com', data: JSON.stringify({
    profile: 'baxter-passive-v1', provider: 'google_dns_doh', target: 'api.example.com', status: 'ok',
    query: 'Google Public DNS DoH', results: 1, checked_at: '2026-11-19T00:00:00Z',
    limitations: ['DKIM requiere un selector conocido.'],
    events: [{ event_type: 'DNS_POSTURE', data: 'spf:present', source_data: 'api.example.com' }],
    checks: [{ check: 'spf', name: 'api.example.com', rrtype: 'TXT', state: 'present',
      records: [{ name: 'api.example.com', type: 'TXT', ttl: 300, data: '"v=spf1 +all"' }],
      dnssec_validated: false, rcode: 0, checked_at: '2026-11-19T00:00:00Z', query: 'https://dns.google/resolve',
      interpretation: 'Se encontró SPF exacto.', issues: [{ code: 'SPF_ALLOW_ALL', message: 'SPF autoriza cualquier origen.', severity: 'alta', evaluable: true, rule: 'CONF-003' }],
    }, { check: 'dkim', name: '<selector>._domainkey.api.example.com', rrtype: 'TXT', state: 'unverified',
      records: [], dnssec_validated: null, rcode: null, checked_at: '2026-11-19T00:00:00Z', query: '',
      interpretation: 'No puede verificarse sin selector.', issues: [],
    }],
  }) }]
}
function chunkedDnsRaw() {
  const full = JSON.parse(dnsRaw()[0].data)
  const checks = full.checks
  delete full.checks
  full.events = []
  full.chunk_type = 'summary'
  full.check_count = checks.length
  return [full, ...checks.map(check => ({
    profile: full.profile, provider: full.provider, target: full.target, status: full.status,
    query: '', results: 0, checked_at: full.checked_at, limitations: [], events: [],
    chunk_type: 'dns_check', check,
  }))].map(report => ({ module: 'sfp_baxter_dns_doh', event_type: 'RAW_RIR_DATA',
    scan_target: 'api.example.com', data: JSON.stringify(report) }))
}
function chunkedUrlscanRaw() {
  const events = [{ event_type: 'URLSCAN_HISTORY', data: 'api.example.com', source_data: 'api.example.com', metadata: { ocurrencias: 2 } },
    { event_type: 'WEBSERVER_TECHNOLOGY', data: 'Next.js 16', source_data: 'api.example.com', metadata: {
      ocurrencias: 2, primera_observacion: '2026-11-01T00:00:00Z', ultima_observacion: '2026-11-03T00:00:00Z',
      reglas_candidatas: ['INFRA-003'], evaluable: false,
    } }]
  const summary = { profile: 'baxter-passive-v1', provider: 'urlscan', target: 'api.example.com', status: 'ok',
    query: 'https://urlscan.io/api/v1/search/', results: 2, checked_at: '2026-11-19T00:00:00Z',
    limitations: ['Historial limitado por el proveedor.'], events: [], chunk_type: 'summary', event_count: events.length }
  const reports = [summary]
  events.forEach((event, eventIndex) => {
    const text = JSON.stringify(event)
    const parts = text.match(/.{1,40}/g) || ['']
    parts.forEach((event_fragment, fragment_index) => reports.push({
      profile: summary.profile, provider: summary.provider, target: summary.target, status: summary.status,
      query: '', results: 0, checked_at: summary.checked_at, limitations: [], events: [], chunk_type: 'provider_event',
      event_index: eventIndex, fragment_index, fragment_count: parts.length, event_fragment,
    }))
  })
  return reports.map(report => ({ module: 'sfp_baxter_urlscan', event_type: 'RAW_RIR_DATA',
    scan_target: 'api.example.com', data: JSON.stringify(report) }))
}
function commonCrawlRaw() {
  return [{ module: 'sfp_baxter_commoncrawl', event_type: 'RAW_RIR_DATA', scan_target: 'api.example.com', data: JSON.stringify({
    profile: 'baxter-passive-v1', provider: 'common_crawl', target: 'api.example.com', status: 'ok',
    query: 'https://index.commoncrawl.org/collinfo.json; hostname exacto', results: 3, unique_urls: 2,
    checked_at: '2026-11-19T00:00:00Z', limitations: ['Evidencia histórica; no prueba exposición actual.'],
    events: [{ event_type: 'COMMONCRAWL_URL', data: 'https://api.example.com/backup.sql', source_data: 'api.example.com',
      observed_at: '2026-10-10T12:00:00Z', metadata: { ocurrencias: 2, categoria: 'documento',
        primera_observacion: '2026-09-10T12:00:00Z', ultima_observacion: '2026-10-10T12:00:00Z',
        estados_http: ['200', '403'], tipos_mime: ['text/html'], posible_exposicion_por_nombre: true,
        evaluable: false, referencias: ['https://index.commoncrawl.org/CC-MAIN-2026-43-index?url=fixture'] } }],
  }) }]
}
function rdapRaw() {
  return [{ module: 'sfp_baxter_rdap', event_type: 'RAW_RIR_DATA', scan_target: 'api.example.co.uk', data: JSON.stringify({
    profile: 'baxter-passive-v1', provider: 'rdap', target: 'api.example.co.uk', status: 'ok',
    query: 'https://rdap.registry.example/uk/domain/example.co.uk', results: 1,
    checked_at: '2026-11-19T00:00:00Z', limitations: ['No demuestra propiedad del cliente.'],
    registrable_domain: 'example.co.uk', is_subdomain: true, registration_state: 'known',
    field_states: { registrador: 'conocido', creacion: 'conocido', vencimiento: 'conocido', estados: 'conocido', nameservers: 'conocido' },
    registrar: { name: 'Fixture Registrar', handle: '999' },
    dates: { registration: '2020-01-01T00:00:00Z', expiration: '2030-01-01T00:00:00Z' },
    statuses: ['active'], nameservers: ['ns1.example.net'],
    references: [{ href: 'https://rdap.registry.example/uk/domain/example.co.uk', rel: 'self' }],
    events: [{ event_type: 'RDAP_REGISTRATION', data: 'example.co.uk', source_data: 'api.example.co.uk',
      metadata: { evaluable: false, propiedad_atribuida: false } }],
  }) }]
}
function fragmentedReport(value, size = 80) {
  const row = value[0]
  const report = JSON.parse(row.data)
  const text = JSON.stringify(report)
  const parts = text.match(new RegExp(`.{1,${size}}`, 'gs')) || ['']
  return parts.map((report_fragment, fragment_index) => ({
    module: row.module, event_type: 'RAW_RIR_DATA', scan_target: row.scan_target,
    data: JSON.stringify({
      profile: report.profile, provider: report.provider, target: report.target,
      status: report.status, query: '', results: 0, checked_at: report.checked_at,
      limitations: [], events: [], chunk_type: 'report_fragment', fragment_index,
      fragment_count: parts.length, report_fragment,
    }),
  }))
}

test('empty is explained differently from failure and unavailable', () => {
  assert.match(render(raw('empty')), /Consulta válida sin registros/)
  assert.match(render(raw('error')), /no equivale a cero resultados/)
  assert.match(render(raw('unavailable')), /no evaluó el activo/)
  assert.match(render(raw('partial')), /historial recuperado está incompleto/)
})
test('asset filtering does not claim another asset was evaluated', () => {
  assert.equal(render(raw('ok'), 'other.example.com'), '')
  assert.match(render(raw('ok'), 'api.example.com'), /api.example.com/)
})
test('evidence explains why a banner is not a vulnerability', () => {
  const html = render(raw('ok', { results: 1, events: [{ event_type: 'WEBSERVER_BANNER', data: 'nginx', source_data: 'api.example.com' }] }))
  assert.match(html, /no prueban vulnerabilidad/)
  assert.match(html, /sfp_baxter_urlscan/)
})
test('malformed and false positive exports do not become completed reports', () => {
  assert.equal(helpers.getSpiderFootReports([{ module: 'sfp_baxter_urlscan', event_type: 'RAW_RIR_DATA', data: '{' }]).length, 0)
  assert.equal(helpers.getSpiderFootReports(raw('ok', { events: [null] })).length, 0)
  const value = raw('ok'); value[0].false_positive = true
  assert.equal(render(value), '')
})
test('DNS modules remain visible as passive discovery evidence', () => {
  const value = [{
    module: 'sfp_dnsresolve', event_type: 'IP_ADDRESS', data: '203.0.113.2',
    source_data: 'api.example.com', scan_target: 'api.example.com', false_positive: 0,
  }]
  const html = render(value, 'api.example.com')
  assert.match(html, /sfp_dnsresolve/)
  assert.match(html, /1 eventos IP_ADDRESS/)
  assert.match(html, /No prueban puertos abiertos ni vulnerabilidades/)
})
test('DNS modules ignore names extracted from Baxter passive report JSON', () => {
  const value = [{
    module: 'sfp_dnsresolve', event_type: 'INTERNET_NAME', data: 'dmarc.api.example.com',
    source_data: JSON.stringify({ profile: 'baxter-passive-v1', provider: 'google_dns_doh' }),
    scan_target: 'api.example.com', false_positive: 0,
  }]
  assert.equal(helpers.getSpiderFootDnsModules(value).length, 0)
  assert.equal(render(value, 'api.example.com'), '')
})
test('DNS DoH report explains posture, exact evidence and risk readiness per asset', () => {
  const html = render(dnsRaw(), 'api.example.com')
  assert.match(html, /Postura DNS del nombre exacto/)
  assert.match(html, /SPF: Presente/)
  assert.match(html, /SPF autoriza cualquier origen/)
  assert.match(html, /Evidencia candidata para CONF-003/)
  assert.match(html, /DKIM: No verificable/)
  assert.match(html, /v=spf1 \+all/)
  assert.equal(render(dnsRaw(), 'other.example.com'), '')
})
test('malformed DNS posture checks are rejected instead of shown as evidence', () => {
  const value = dnsRaw()
  const report = JSON.parse(value[0].data)
  report.checks[0].state = 'invented'
  value[0].data = JSON.stringify(report)
  assert.equal(render(value), '')
})
test('chunked DNS reports are reassembled and incomplete exports stay partial', () => {
  const complete = chunkedDnsRaw()
  assert.equal(helpers.getSpiderFootReports(complete).length, 1)
  assert.match(render(complete), /SPF: Presente/)
  const incomplete = complete.slice(0, -1)
  assert.match(render(incomplete), /Consulta parcial/)
  assert.match(render(incomplete), /Solo se recuperaron 1 de 2 comprobaciones DNS/)
})
test('chunked urlscan history explains consolidated technical evidence', () => {
  const complete = chunkedUrlscanRaw()
  const html = render(complete, 'api.example.com')
  assert.match(html, /Historial público exacto: 2 resultados/)
  assert.match(html, /Next.js 16/)
  assert.match(html, /2 observaciones/)
  assert.match(html, /INFRA-003/)
  assert.match(html, /no evaluable sin corroboración actual/)
  const incomplete = complete.slice(0, -1)
  assert.match(render(incomplete), /Consulta parcial/)
  assert.match(render(incomplete), /Solo se recuperaron 1 de 2 evidencias del proveedor/)
})
test('Common Crawl report distinguishes historical names from confirmed leaks', () => {
  const html = render(commonCrawlRaw(), 'api.example.com')
  assert.match(html, /3 capturas históricas, consolidadas en 2 URLs exactas/)
  assert.match(html, /backup\.sql/)
  assert.match(html, /no confirma filtración/)
  assert.match(html, /ni activa FUGA-002/)
  assert.match(html, /Referencia de índice 1/)
  assert.equal(render(commonCrawlRaw(), 'other.example.com'), '')
})
test('RDAP report explains parent registration without attributing ownership to a subdomain', () => {
  const html = render(rdapRaw(), 'api.example.co.uk')
  assert.match(html, /dominio registrable <strong>example\.co\.uk/)
  assert.match(html, /Fixture Registrar/)
  assert.match(html, /2030-01-01/)
  assert.match(html, /ns1\.example\.net/)
  assert.match(html, /No atribuyen automáticamente propiedad/)
  assert.equal(render(rdapRaw(), 'other.example.co.uk'), '')
})
test('fragmented provider reports are reassembled without losing evidence', () => {
  const common = fragmentedReport(commonCrawlRaw())
  assert.match(render(common, 'api.example.com'), /backup\.sql/)
  const rdap = fragmentedReport(rdapRaw())
  assert.match(render(rdap, 'api.example.co.uk'), /Fixture Registrar/)
  const incomplete = common.slice(0, -1)
  assert.match(render(incomplete, 'api.example.com'), /fragmentos del reporte/)
})
