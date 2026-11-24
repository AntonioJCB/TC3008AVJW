import SpiderFootEvidence from './SpiderFootEvidence'
import NvdPotentialEvidence, { isPotentialVulnerability } from './NvdPotentialEvidence'
import { useEffect, useState } from 'react'
import { isCrtshReport, isHarvesterReport } from '../services/sourceReports'
import { loadClientData, loadSourceRawResult } from '../services/clientData'
import type { ClientData, Source } from '../services/clientData'
import { isActiveSource, sourceIssueSummary } from '../services/sourcePolicy'
import { exportOverviewToExcel } from '../services/exportOverview'
import LiveSourceLogDialog from '../screens/sources/components/LiveSourceLogDialog'
import './analysisReport.css'

const meanings: Record<string, string> = {
  info_host: 'Información técnica histórica (banner, software o puerto sin transporte). Por sí sola no activa una regla de riesgo.',
  descubierto: 'Identificación pública del activo; por sí sola no demuestra vulnerabilidad.',
  resuelve_a: 'Relación DNS entre un nombre y una IP; no demuestra propiedad exclusiva ni exposición de puertos.',
  certificado: 'Certificado publicado en CT; no confirma el certificado instalado actualmente.',
  correo: 'Dirección publicada; no prueba una filtración de credenciales.',
  servicio_expuesto: 'Servicio reportado por una fuente pública; revisar alcance, fecha y regla asociada.',
  cve: 'Vulnerabilidad reportada por una fuente; requiere verificar su atribución al activo.',
}
const purposes: Record<string, string> = {
  'crt.sh': 'Busca nombres y certificados históricos en Certificate Transparency. Una consulta correcta sin registros indica que no encontró certificados; no verifica el TLS actual.',
  theHarvester: 'Consulta proveedores públicos para encontrar nombres, IPs y correos. La ausencia de resultados no demuestra ausencia de exposición.',
  SpiderFoot: 'Consulta registros públicos existentes para cada activo compatible y autorizado. Distingue banners históricos, software, servicios y referencias CVE; cada proveedor conserva su fecha y sus limitaciones.',
  Web: 'Consulta la superficie web autorizada y conserva las observaciones y errores de cada objetivo.',
}
export default function AnalysisReport({ data }: { data: ClientData }) {
  const [selected, setSelected] = useState('')
  const [snapshot, setSnapshot] = useState<ClientData | null>(null)
  const [error, setError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  useEffect(() => {
    if (!selected) return
    let active = true
    void loadClientData(data.organization.id, selected).then(value => { if (active) setSnapshot(value) }).catch(() => { if (active) setError('No se pudo cargar el reporte seleccionado.') })
    return () => { active = false }
  }, [selected, data.organization.id])
  const reportData = selected ? snapshot : data
  async function exportExcel() {
    if (!reportData?.latestFinishedScan || exporting) return
    setExporting(true)
    setExportError('')
    try { await exportOverviewToExcel(reportData, reportData.latestFinishedScan) }
    catch { setExportError('No se pudo generar el archivo de Excel. Intenta de nuevo.') }
    finally { setExporting(false) }
  }
  return <div className="analysis-page">
    <header className="analysis-page-heading"><div><span className="eyebrow">OPERACIÓN Y EVIDENCIA</span><h2>Análisis</h2><p>Consulta cada ejecución, su cobertura y la evidencia que sustenta el reporte.</p></div></header>
    <div className="analysis-report-toolbar"><label htmlFor="analysis-report-select"><span>Análisis del reporte</span><select id="analysis-report-select" value={selected} onChange={event => { setSelected(event.target.value); setSnapshot(null); setError(''); setExportError('') }}><option value="">Último análisis terminado</option>{data.scans.filter(scan => scan.finalizado_en && scan.estado !== 'cancelado').map(scan => <option key={scan.id} value={scan.id}>{new Date(scan.finalizado_en!).toLocaleString('es-MX')} · {scan.estado}</option>)}</select></label><span className="analysis-current-state" role="status">{selected && !snapshot ? 'Cargando…' : reportData?.latestFinishedScan?.estado ?? 'Sin análisis'}</span><button type="button" className="overview-export-button" onClick={() => void exportExcel()} disabled={exporting || !reportData?.latestFinishedScan}>{exporting ? 'Generando Excel…' : 'Exportar a Excel'}</button></div>
    {exportError && <p className="client-error" role="alert">{exportError}</p>}
    {error ? <p className="client-error" role="alert">{error}</p> : selected && !snapshot ? <p role="status">Cargando reporte…</p> : reportData?.latestFinishedScan ? <ReportContent key={selected || data.latestFinishedScan?.id} data={reportData} /> : <p className="client-empty" role="status">Todavía no hay análisis terminados. El reporte aparecerá al finalizar una ejecución.</p>}
  </div>
}

function ReportContent({ data }: { data: ClientData }) {
  const [raws, setRaws] = useState<Record<string, unknown>>({})
  const [rawErrors, setRawErrors] = useState<string[]>([])
  useEffect(() => {
    let active = true
    const results = data.sourceResults.filter(result => result.resultado_crudo_id)
    void Promise.allSettled(results.map(result => loadSourceRawResult(result.resultado_crudo_id!))).then(values => {
      if (!active) return
      const loaded: Record<string, unknown> = {}
      const failed: string[] = []
      values.forEach((value, index) => {
        if (value.status === 'fulfilled' && value.value) loaded[results[index].fuente_id] = value.value.contenido
        else failed.push(results[index].fuente_id)
      })
      setRaws(loaded); setRawErrors(failed)
    })
    return () => { active = false }
  }, [data.sourceResults])
  const [view, setView] = useState('Vista general')
  const [source, setSource] = useState<Source | null>(null)
  const scan = data.latestFinishedScan
  const risk = data.risks.find(item => item.escaneo_id === scan?.id)
  const potentialRisk = risk?.cobertura?.riesgo_potencial
  const globalRisk = risk?.cobertura?.riesgo_global_estimado
  const formatScore = (value: number | null | undefined) => value == null ? '—' : value > 0 && value < 0.1 ? '<0.1' : value.toFixed(1)
  const coverage = risk?.cobertura?.infraestructura
  const activeSources = data.sources.filter(item => isActiveSource(item.nombre))
  const sourceNames = new Map(data.sources.map(item => [item.id, item.nombre]))
  const assets = coverage?.activos ?? data.assets.map(asset => ({ ...asset, incluido: false, consultado: false, motivo: 'Este análisis histórico no conserva cobertura por objetivo; no se puede inferir de los descubrimientos.', consultas: [], evaluacion_seguridad: 'No verificable con el registro disponible.' }))
  const queries = Object.entries(coverage?.fuentes ?? {}).flatMap(([name, result]) => result.consultas.map(query => ({ ...query, fuente: name })))
  const pending = assets.filter(asset => asset.motivo)
  const duration = scan?.iniciado_en && scan.finalizado_en ? `${Math.round((Date.parse(scan.finalizado_en) - Date.parse(scan.iniciado_en)) / 1000)} s` : 'No disponible'
  const findings = data.findings.filter(item => ['abierto', 'nuevo', 'revisado', 'aceptado'].includes(item.estado))
  const contributing = findings.filter(item => Number(item.evidencia?.aporte) > 0)
  const potentialVulnerabilities = data.observations.filter(isPotentialVulnerability)
  const verifiedCves = data.observations.filter(item => item.atributo === 'cve' && item.datos.verificado === true)
  const sourceResult = source ? data.sourceResults.find(item => item.fuente_id === source.id) : null
  const sourceDuration = sourceResult?.iniciado_en && sourceResult.finalizado_en ? `${Math.round((Date.parse(sourceResult.finalizado_en) - Date.parse(sourceResult.iniciado_en)) / 1000)} s` : 'No disponible'
  if (!scan) return null
  return <section className="content-card analysis-report" aria-label="Reporte del análisis">
    <div className="card-heading"><div><h2>Reporte del análisis</h2><p>{data.organization.dominio_principal} · {scan.estado} · {duration}</p></div></div>
    <nav className="report-tabs" aria-label="Vistas del reporte">{['Vista general', 'Por herramienta', 'Por activo', 'Detalle técnico'].map(tab => <button type="button" key={tab} aria-pressed={view === tab} onClick={() => setView(tab)}>{tab}</button>)}</nav>
    {view === 'Vista general' && <>
      <div className="report-metrics">{[
        ['Activos en inventario', assets.length], ['Con consultas completadas', coverage ? assets.filter(asset => asset.consultado).length : 'No registrado'],
        ['Observaciones', data.observations.length], ['Hallazgos vigentes', findings.length], ['Risk Score', risk?.puntaje_global ?? 'No disponible'],
      ].map(([label, value]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}</div>
      <div className="report-summary-lead"><strong>{scan.estado === 'completado' ? 'Análisis completado' : `Análisis ${scan.estado}`}</strong><p>{contributing.length ? `${contributing.length} hallazgos vigentes aportan al puntaje.` : 'No hay hallazgos puntuables en este análisis.'} {pending.length ? `${pending.length} activos tienen limitaciones o consultas pendientes.` : 'Revisa la cobertura antes de interpretar los resultados.'}</p></div>
      <div className="report-disclosures">
        <details><summary>Descubrimientos y observaciones</summary><p>Herramientas: {activeSources.map(item => item.nombre).join(', ')}. Una consulta completada acredita la búsqueda pública registrada; no certifica que el activo carezca de vulnerabilidades.</p><p>{data.observations.length} observaciones asociadas a {new Set(data.observations.map(item => item.activo_id)).size} activos. {Object.entries(meanings).filter(([kind]) => data.observations.some(item => item.atributo === kind)).map(([kind, meaning]) => `${data.observations.filter(item => item.atributo === kind).length} de tipo ${kind}: ${meaning}`).join(' ')}</p><p>{potentialVulnerabilities.length} vulnerabilidades potenciales enriquecidas por NVD/OSV y {verifiedCves.length} CVE verificadas por una fuente. Las coincidencias conservan producto o paquete, versión y evidencia original, pero no aportan al Risk Score.</p></details>
        <details><summary>Interpretación del riesgo</summary><p>{contributing.length ? `${contributing.length} hallazgos vigentes aportan al puntaje. Revisa el activo y la evidencia en la vista por activo.` : 'No hay hallazgos puntuables en los datos de este análisis. Esto no demuestra que la infraestructura esté libre de vulnerabilidades.'} El motor combina los aportes con rendimientos decrecientes; no son una suma directa.</p><p>Reglas evaluadas: {risk?.cobertura?.evaluadas?.join(', ') || 'Sin desglose registrado'}. Las señales informativas con peso cero no aumentan el riesgo.</p></details>
        <details><summary>Limitaciones y pendientes</summary><p>{coverage ? `${pending.length} activos tienen una limitación o consulta pendiente. ${coverage.objetivos_pendientes.length} objetivos quedaron pendientes por los límites de ejecución.` : 'No existe trazabilidad suficiente para reconstruir la cobertura de este análisis histórico.'} {risk?.es_parcial ? 'El resultado es parcial.' : ''}</p><p>Las fuentes actuales pueden aportar descubrimientos sin disponer de evidencia de servicios, versiones o CVE. Los certificados históricos y las relaciones DNS no sustituyen esas comprobaciones.</p></details>
      </div>
      <p className="report-conclusion">{contributing.length ? 'Hay riesgos documentados que requieren revisión en los activos señalados.' : 'Se conserva el inventario y la evidencia pública recibida; no se identificaron riesgos puntuables.'} {pending.length ? 'Consulta los motivos por activo antes de interpretar el resultado como una evaluación de toda la infraestructura.' : 'Las consultas registradas no verifican riesgos que las fuentes configuradas no pueden observar.'}</p>
    </>}
    {view === 'Por herramienta' && activeSources.map(item => {
      const result = data.sourceResults.find(row => row.fuente_id === item.id)
      const report = coverage?.fuentes[item.nombre]
      const raw = raws[item.id]
      const crt = isCrtshReport(raw) ? raw : null
      const harvester = isHarvesterReport(raw) ? raw : null
      return <article className="report-source" key={item.id}><h3>{item.nombre}</h3><p className="report-source-lead">{result?.estado ?? 'Sin ejecutar'} · {result?.observaciones_generadas ?? 0} observaciones · {result?.activos_nuevos ?? 0} activos nuevos{result?.error ? ` · ${sourceIssueSummary(result.error)}` : ''}</p>
        <details className="report-source-disclosure"><summary>Contexto, consultas y evidencia</summary><p>{purposes[item.nombre]}</p>{(result?.error || report?.error) && <p role="status">{result?.error || report?.error}</p>}
        {rawErrors.includes(item.id) && <p role="alert">No se pudo cargar la respuesta original. Los contadores y las consultas guardadas siguen disponibles.</p>}
        {crt && <><p>{crt.entries.length} registros de certificados recibidos.</p><details><summary>Consultas de Certificate Transparency</summary><ul>{crt.queries.map((query, index) => <li key={index}>{query.query}: {query.status === 'ok' ? `${query.entries} registros recibidos` : `Consulta fallida: ${query.error || query.status}`}</li>)}</ul></details></>}
        {harvester && <><p>{harvester.items.length} resultados públicos recibidos en {harvester.runs.length} objetivos.</p><details><summary>Proveedores consultados por objetivo</summary>{harvester.runs.map((run, index) => <div key={index}><strong>{run.target}</strong><ul>{run.source_executions.map((execution, i) => <li key={i}>{execution.source}: {execution.status} · {execution.result_count} resultados {execution.stop_reason} {execution.error_type}</li>)}</ul></div>)}</details></>}
        {item.nombre === 'SpiderFoot' && <SpiderFootEvidence raw={raw} />}
        {item.nombre === 'SpiderFoot' && <NvdPotentialEvidence observations={data.observations.filter(obs => obs.fuente_id === item.id)} />}
        {item.nombre === 'SpiderFoot' && <p>{data.observations.filter(obs => obs.fuente_id === item.id && obs.atributo === 'resuelve_a').length} relaciones DNS y {data.observations.filter(obs => obs.fuente_id === item.id && obs.atributo === 'descubierto').length} observaciones de identificación. Los nombres e IPs asociados están en la vista por activo.</p>}
        {report ? <ul>{report.consultas.map((query, index) => <li key={index}><strong>{query.objetivo}</strong>: {query.metodo} · {query.estado}{query.error ? ` · ${query.error}` : ''}</li>)}</ul> : <p>No se guardó un registro por objetivo en este análisis.</p>}</details>
        <button type="button" onClick={() => setSource(item)}>Ver proveedores, respuestas y evidencia de {item.nombre}</button></article>
    })}
    {view === 'Por activo' && <><p>Cada ficha distingue consultas realizadas, observaciones recibidas y riesgos reportados. Los servicios consultados por IP no implican verificación individual del puerto.</p>{assets.map(asset => {
      const observations = data.observations.filter(item => item.activo_id === asset.id)
      const potential = observations.filter(isPotentialVulnerability)
      const related = data.findings.filter(item => item.activo_id === asset.id)
      return <details className="report-asset" key={asset.id}><summary>{asset.valor} · {asset.consultado ? 'Con consulta pública completada' : 'Sin consulta completada registrada'} · {observations.length} observaciones · {related.length} hallazgos</summary>
        <p>{asset.motivo || 'Consultas registradas completadas.'} {asset.evaluacion_seguridad}</p>
        <ul>{asset.consultas.map((query, index) => <li key={index}>{query.fuente}: {query.metodo} · {query.estado} {query.error}</li>)}</ul>
        {activeSources.filter(item => item.nombre === 'SpiderFoot').map(item => <SpiderFootEvidence key={item.id} raw={raws[item.id]} target={'objetivo' in asset && typeof asset.objetivo === 'string' ? asset.objetivo : asset.valor} />)}
        <NvdPotentialEvidence observations={potential} />
        {observations.filter(obs => !isPotentialVulnerability(obs)).map(obs => <div key={obs.id}><p><strong>{sourceNames.get(obs.fuente_id)} · {obs.atributo}</strong>: {meanings[obs.atributo] || 'Información recibida de la fuente; revisar la evidencia antes de atribuir riesgo.'}</p><p>{String(obs.datos?.valor || obs.datos?.cve || '')} {obs.datos?.modulo ? `· Módulo: ${String(obs.datos.modulo)}` : ''} {obs.datos?.verificado === true ? '· Verificada por la fuente.' : obs.datos?.verificado === false ? '· Potencial o sin corroboración suficiente: no aporta por CVE.' : ''}</p><details><summary>Ver evidencia</summary><pre>{JSON.stringify(obs.datos, null, 2)}</pre></details></div>)}
        {related.map(finding => <div key={finding.id}><p>{data.rules.find(rule => rule.id === finding.regla_id)?.codigo} · {finding.severidad} · {finding.estado} · Aporte: {finding.evidencia?.aporte === undefined ? 'No registrado' : String(finding.evidencia.aporte)}</p><pre>{JSON.stringify(finding.evidencia, null, 2)}</pre></div>)}
      </details>
    })}</>}
    {view === 'Detalle técnico' && <><p>Análisis: {scan.id}. {queries.length} registros de consulta. El detalle utiliza las mismas respuestas guardadas que los popups de Fuentes.</p>
      {(risk || potentialRisk || globalRisk) && <section className="analysis-estimates" aria-label="Estimaciones de riesgo del análisis">
        <h3>Riesgo y límites</h3>
        <div className="analysis-estimate-grid">
          <div className="confirmed"><span>Confirmado</span><strong>{formatScore(risk?.puntaje_global)} <small>/100</small></strong><p>Hallazgos verificados; puntaje oficial redondeado.</p></div>
          <div className="potential"><span>Potencial</span><strong>{formatScore(potentialRisk?.puntaje_global)} <small>/100</small></strong><p>{potentialRisk?.hallazgos ?? 0} señales potenciales puntuables.</p></div>
          <div className="global"><span>Global estimado</span><strong>{formatScore(globalRisk?.puntaje_global)} <small>/100</small></strong><p>Combina aportes antes del redondeo.</p></div>
        </div>
        <details><summary>Cómo interpretar estas cifras y ver contribuciones</summary><p>El potencial depende de señales históricas puntuables. Un cero indica que no hubo aportes potenciales en este análisis. El global utiliza aportes con decimales y puede diferir del confirmado redondeado.</p>{globalRisk && (globalRisk.contribuciones.length ? <ul>{globalRisk.contribuciones.map(item => <li key={`${item.activo_id}-${item.regla}`}>{item.regla} · {item.nivel_evidencia} · {data.assets.find(asset => asset.id === item.activo_id)?.valor ?? item.activo_id}: {formatScore(item.aporte)}</li>)}</ul> : <p>No hay contribuciones puntuables.</p>)}</details>
      </section>}
      <details><summary>Reglas evaluadas y omitidas</summary><pre>{JSON.stringify(risk?.cobertura, null, 2)}</pre></details>{activeSources.map(item => <button type="button" key={item.id} onClick={() => setSource(item)}>Respuesta de {item.nombre}</button>)}</>}
    {source && <LiveSourceLogDialog source={source} result={sourceResult ?? null} statusLabel={!sourceResult ? 'Sin ejecutar' : sourceResult.estado === 'completado' ? (sourceResult.error ? 'Parcial' : 'Saludable') : sourceResult.estado === 'fallido' ? 'Fallida' : sourceResult.estado} duration={sourceDuration} queries={risk?.cobertura?.infraestructura?.fuentes[source.nombre]?.consultas ?? []} onClose={() => setSource(null)} />}
  </section>
}
