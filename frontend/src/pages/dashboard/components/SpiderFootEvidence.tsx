import { getSpiderFootDnsModules, getSpiderFootReports } from '../services/sourceReports'

const meanings: Record<string, string> = {
  INTERNET_NAME: 'registros históricos del nombre consultado',
  WEBSERVER_BANNER: 'banners web históricos; pueden identificar producto o versión, pero no prueban vulnerabilidad',
  SOFTWARE_USED: 'identificaciones de software o CPE publicadas por el proveedor',
  TCP_PORT_OPEN: 'servicios TCP reportados por el proveedor; las reglas revisan puertos de administración y bases de datos',
  UDP_PORT_OPEN: 'servicios UDP reportados por el proveedor; no se convierten en TCP para puntuar',
  PROVIDER_PORT: 'puertos publicados sin transporte; no activan reglas de servicios TCP',
  VULNERABILITY_CVE_UNKNOWN: 'referencias CVE; solo las verificadas explícitamente por el proveedor pueden contribuir con este perfil',
  TCP_PORT_OPEN_BANNER: 'banners históricos de servicios; no se obtuvieron conectándose al activo',
  UDP_PORT_OPEN_INFO: 'información histórica de servicios UDP',
  DNS_POSTURE: 'comprobaciones estructuradas de postura DNS vinculadas al nombre exacto',
  COMMONCRAWL_URL: 'URLs históricas del hostname exacto, deduplicadas sin afirmar exposición actual',
  RDAP_REGISTRATION: 'datos públicos del registro del dominio registrable; no prueban propiedad del cliente',
  URLSCAN_HISTORY: 'resumen consolidado de análisis históricos exactos',
  URLSCAN_HTTP_STATUS: 'estados HTTP históricos de la página principal',
  URLSCAN_REDIRECT: 'redirecciones históricas desde o hacia el nombre consultado',
  URLSCAN_HTTP_REDIRECT: 'comprobación histórica explícita de redirección HTTP a HTTPS',
  URLSCAN_TLS_CERTIFICATE: 'metadatos históricos TLS; no demuestran un fallo de validación ni el estado actual',
  URLSCAN_PAGE_METADATA: 'metadatos históricos de red y contenido',
  URLSCAN_SECURITY_HEADERS: 'cabeceras HTTP de seguridad observadas en una respuesta histórica completa',
  URLSCAN_VERDICT: 'señales históricas de riesgo de urlscan; no son vulnerabilidades verificadas',
  WEBSERVER_TECHNOLOGY: 'tecnologías históricas detectadas; requieren corroboración antes de evaluar vulnerabilidades',
}

const checkNames: Record<string, string> = {
  a: 'IPv4 (A)', aaaa: 'IPv6 (AAAA)', cname: 'Alias (CNAME)', mx: 'Correo (MX)', txt: 'Texto (TXT)',
  spf: 'SPF', dmarc: 'DMARC', dkim: 'DKIM', caa: 'Autoridades de certificación (CAA)',
  ns: 'Servidores DNS (NS)', soa: 'Autoridad de zona (SOA)', ds: 'Delegación DNSSEC (DS)',
  dnssec: 'Validación DNSSEC', mta_sts: 'MTA-STS', tls_rpt: 'TLS-RPT',
}

const stateNames: Record<string, string> = {
  present: 'Presente', absent: 'Ausente', error: 'Error', unverified: 'No verificable', not_applicable: 'No aplicable',
}

export default function SpiderFootEvidence({ raw, target }: { raw: unknown; target?: string }) {
  const reports = getSpiderFootReports(raw).filter(report => !target || report.target === target)
  const dnsModules = getSpiderFootDnsModules(raw).filter(report => !target || report.target === target)
  if (!reports.length && !dnsModules.length) return null
  return <div className="spiderfoot-evidence">
    {dnsModules.length > 0 && <details><summary>Módulos DNS que aportaron evidencia</summary>
      {dnsModules.map(report => <article key={`${report.module}-${report.target}`}>
        <p><strong>{report.target} · {report.module}</strong></p>
        <ul>{Object.entries(report.events).map(([kind, count]) => <li key={kind}>{count} eventos {kind}.</li>)}</ul>
        <p>Estos eventos describen nombres, registros o resoluciones DNS. No prueban puertos abiertos ni vulnerabilidades.</p>
      </article>)}
    </details>}
    {reports.map((report, index) => {
    const counts = report.events.reduce<Record<string, number>>((acc, event) => ({ ...acc, [event.event_type]: (acc[event.event_type] || 0) + 1 }), {})
    const status = report.status === 'empty' ? 'Consulta válida sin registros; no demuestra ausencia de exposición.'
      : report.status === 'ok' ? `Consulta completada: ${report.results} registros del proveedor.`
      : report.status === 'partial' ? 'Consulta parcial; el historial recuperado está incompleto.'
      : report.status === 'unavailable' ? 'Capacidad no disponible; este proveedor no evaluó el activo.'
      : 'Consulta fallida; no equivale a cero resultados.'
    return <article key={`${report.module}-${report.target}-${index}`}>
      <p><strong>{report.target} · {report.provider}</strong></p>
      <p>{status} {report.error}</p>
      {report.provider === 'google_dns_doh' && report.checks && <div>
        <p>Postura DNS del nombre exacto. Los destinos de proveedores se muestran como evidencia, pero no se incorporan al inventario.</p>
        {report.checks.map(check => <details key={`${check.check}-${check.name}`} open={check.issues.length > 0 || check.state === 'error'}>
          <summary>{checkNames[check.check] || check.check}: {stateNames[check.state] || check.state}</summary>
          <p>{check.interpretation}</p>
          {check.records.length > 0 && <ul>{check.records.map((record, i) => <li key={`${record.type}-${record.data}-${i}`}>
            {record.name} · {record.type} · TTL {record.ttl ?? 'no indicado'} · {record.data}
          </li>)}</ul>}
          {check.cname_target_assessment && <p>
            Destino CNAME: {check.cname_target_assessment.target || 'no determinable'} · {check.cname_target_assessment.interpretation}
            {' '}La reclamabilidad no fue verificada y el destino no se atribuye al cliente.
          </p>}
          {check.issues.length > 0 && <ul>{check.issues.map(issue => <li key={issue.code}>
            {issue.message} {issue.evaluable && issue.rule ? `Evidencia candidata para ${issue.rule}; la regla conserva su activación y peso actuales.` : 'Observación informativa.'}
          </li>)}</ul>}
          <p>Consultado: {check.checked_at}. DNSSEC validado por el resolvedor: {check.dnssec_validated === true ? 'sí' : check.dnssec_validated === false ? 'no consta' : 'no verificable'}.</p>
        </details>)}
      </div>}
      {report.provider === 'urlscan' && <div>
        <p>Historial público exacto: {report.results} resultados. No se solicitó ningún escaneo nuevo.</p>
        {report.header_evaluation && <p>Cabeceras HTTP: {report.header_evaluation.complete} de {report.header_evaluation.requested} respuestas de detalle completas; {report.header_evaluation.unverifiable} no verificables. Solo evidencia de hasta {report.header_evaluation.max_age_days} días puede ser candidata.</p>}
        {report.redirect_evaluation && <p>HTTP→HTTPS: {report.redirect_evaluation.complete} de {report.redirect_evaluation.requested} cadenas verificables; {report.redirect_evaluation.unverifiable} no verificables. La ausencia de detalle no se interpreta como ausencia de redirección.</p>}
        {report.events.filter(event => event.event_type !== 'URLSCAN_HISTORY').map((event, i) => {
          const metadata = event.metadata || {}
          const occurrences = typeof metadata.ocurrencias === 'number' ? metadata.ocurrencias : 1
          const first = typeof metadata.primera_observacion === 'string' ? metadata.primera_observacion : null
          const last = typeof metadata.ultima_observacion === 'string' ? metadata.ultima_observacion : null
          const candidates = Array.isArray(metadata.reglas_candidatas) ? metadata.reglas_candidatas.join(', ') : ''
          const issues = Array.isArray(metadata.issues) ? metadata.issues.filter(issue => issue && typeof issue === 'object') as Array<Record<string, unknown>> : []
          return <details key={`${event.event_type}-${event.data}-${i}`}>
            <summary>{meanings[event.event_type] || event.event_type}: {event.data}</summary>
            <p>{occurrences} observaciones{first || last ? `; periodo ${first || 'no indicado'} — ${last || 'no indicado'}` : ''}.</p>
            {event.event_type === 'URLSCAN_SECURITY_HEADERS' && <p>
              Respuesta completa: {metadata.cabeceras_completas === true ? 'sí' : 'no verificable'}. Evidencia histórica: sí; verificación actual: no.
              {typeof metadata.antiguedad_dias === 'number' ? ` Antigüedad: ${metadata.antiguedad_dias} días.` : ''}
            </p>}
            {event.event_type === 'URLSCAN_HTTP_REDIRECT' && <p>
              {String(metadata.url_inicial || 'URL inicial no indicada')} → {String(metadata.url_final || 'URL final no indicada')} · HTTP {String(metadata.estado_http ?? 'no indicado')}.
              Evidencia histórica: sí; verificación actual: no.
            </p>}
            {issues.length > 0 && <ul>{issues.map((issue, issueIndex) => <li key={`${String(issue.code)}-${issueIndex}`}>{String(issue.message || issue.code)} {issue.evaluable === true ? 'Evidencia candidata.' : 'No evaluable.'}</li>)}</ul>}
            {candidates && <p>Reglas relacionadas: {candidates}. {['URLSCAN_SECURITY_HEADERS', 'URLSCAN_HTTP_REDIRECT', 'URLSCAN_TLS_CERTIFICATE'].includes(event.event_type) && metadata.evaluable === true ? 'Se conserva como hallazgo histórico potencial; no confirma la configuración actual ni puntúa mientras la regla permanezca inactiva.' : 'Evidencia histórica no evaluable sin corroboración actual.'}</p>}
          </details>
        })}
      </div>}
      {report.provider === 'common_crawl' && <div>
        <p>Common Crawl: {report.results} capturas históricas, consolidadas en {report.unique_urls ?? report.events.length} URLs exactas. No se descargaron WARC ni se contactó al activo.</p>
        {report.events.filter(event => event.event_type === 'COMMONCRAWL_URL').map((event, i) => {
          const metadata = event.metadata || {}
          const occurrences = typeof metadata.ocurrencias === 'number' ? metadata.ocurrencias : 1
          const first = typeof metadata.primera_observacion === 'string' ? metadata.primera_observacion : null
          const last = typeof metadata.ultima_observacion === 'string' ? metadata.ultima_observacion : null
          const category = typeof metadata.categoria === 'string' ? metadata.categoria : 'url'
          const statuses = Array.isArray(metadata.estados_http) ? metadata.estados_http.filter(value => typeof value === 'string').join(', ') : ''
          const mimes = Array.isArray(metadata.tipos_mime) ? metadata.tipos_mime.filter(value => typeof value === 'string').join(', ') : ''
          const sensitivePath = metadata.posible_exposicion_por_nombre === true
          const sensitiveDocument = metadata.posible_documento_sensible === true
          const document = metadata.documento_indexado === true
          const references = Array.isArray(metadata.referencias) ? metadata.referencias.filter(value => typeof value === 'string' && value.startsWith('https://index.commoncrawl.org/')).slice(0, 3) as string[] : []
          return <details key={`${event.data}-${i}`} open={sensitivePath}>
            <summary>{category}: {event.data}</summary>
            <p>{occurrences} capturas{first || last ? `; periodo ${first || 'no indicado'} — ${last || 'no indicado'}` : ''}. HTTP: {statuses || 'no indicado'}. MIME: {mimes || 'no indicado'}.</p>
            <p>{sensitiveDocument
              ? 'El nombre del documento parece sensible, pero no confirma su contenido, una filtración ni activa FUGA-002.'
              : sensitivePath ? 'La ruta parece sensible, pero no es evidencia documental, no confirma filtración ni activa FUGA-002.'
              : document ? 'Documento histórico indexado sin evidencia suficiente de contenido sensible.'
                : 'Registro histórico informativo; no confirma exposición actual.'}</p>
            {references.length > 0 && <ul>{references.map((reference, referenceIndex) => <li key={reference}><a href={reference} target="_blank" rel="noreferrer">Referencia de índice {referenceIndex + 1}</a></li>)}</ul>}
          </details>
        })}
      </div>}
      {report.provider === 'rdap' && <div>
        <p>RDAP consultó el dominio registrable <strong>{report.registrable_domain || 'no determinado'}</strong>{report.is_subdomain ? ` para contextualizar ${report.target}` : ''}.</p>
        {report.registration_state === 'absent' ? <p>El servicio autoritativo no publicó un objeto de dominio para la consulta. No se interpreta como riesgo ni como prueba concluyente de disponibilidad.</p> : <>
          <p>Registrador: {report.registrar?.name || report.registrar?.handle || 'ausente o no verificable'}.</p>
          <p>Creación: {report.dates?.registration || 'ausente o no verificable'}. Vencimiento: {report.dates?.expiration || report.dates?.['registrar expiration'] || 'ausente o no verificable'}.</p>
          <p>Estados: {report.statuses?.join(', ') || 'ausentes o no verificables'}.</p>
          <p>Nameservers: {report.nameservers?.join(', ') || 'ausentes o no verificables'}.</p>
          {report.field_states && <p>Disponibilidad de campos: {Object.entries(report.field_states).map(([field, state]) => `${field}: ${state}`).join('; ')}.</p>}
          <p>Estos datos pertenecen al registro del dominio padre. No atribuyen automáticamente propiedad, control ni riesgos al subdominio o al cliente.</p>
          {report.references && report.references.length > 0 && <ul>{report.references.filter(reference => reference.href.startsWith('https://')).slice(0, 5).map((reference, i) => <li key={reference.href}><a href={reference.href} target="_blank" rel="noreferrer">Referencia RDAP {i + 1}</a></li>)}</ul>}
        </>}
      </div>}
      {Object.entries(counts).length > 0 && <ul>{Object.entries(counts).map(([kind, count]) => <li key={kind}>{count} {meanings[kind] || kind}.</li>)}</ul>}
      {report.limitations.map((limit, i) => <p key={i}>{limit}</p>)}
      <details><summary>Módulo y consulta registrada</summary><p>{report.module} · Consultado: {report.checked_at}</p><p>{report.query || 'No se envió una consulta al proveedor.'}</p></details>
    </article>
    })}</div>
}
