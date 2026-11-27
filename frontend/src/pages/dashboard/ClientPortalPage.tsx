import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useAuth } from '../../controllers/useAuth'
import DashboardHeader from './components/header/DashboardHeader'
import InfoTip from './components/InfoTip'
import ScanProgressPanel from './components/ScanProgressPanel'
import RiskTrendChart from './screens/overview/components/RiskTrendChart'
import LiveSourcesScreen from './screens/sources/LiveSourcesScreen'
import AssetsScreen from './screens/assets/AssetsScreen'
import RelationsScreen from './screens/relations/RelationsScreen'
import FindingsScreen from './screens/findings/FindingsScreen'
import HistoryScreen from './screens/history/HistoryScreen'
import AssistantScreen from './screens/assistant/AssistantScreen'
import SettingsScreen from './screens/settings/SettingsScreen'
import DashboardSidebar from './components/sidebar/DashboardSidebar'
import { navigation, type DashboardSection } from './navigation'
import { loadClientData, scanSources, type ClientData, type Risk, type Scan } from './services/clientData'
import { createScan, executeScan, getScanProgress, resolveFinding, ScanRequestError, stopScan, type ScanProgress } from './services/scanActions'
import { liveFindings, liveHistoryScans } from './services/liveAdapters'
import AnalysisReport from './components/AnalysisReport'
import { isDisabledSourceResult } from './services/sourcePolicy'
import './dashboard.css'
import './typography.css'
import './clientPortal.css'
import './screens/overview/overview.css'
import './screens/assets/assets.css'
import './screens/relations/relations.css'
import './screens/sources/sources.css'
import './screens/findings/findings.css'
import './screens/history/history.css'

const sections = new Set<DashboardSection>(navigation.map((item) => item.section))
const dateTime = (value: string | null | undefined) => value
  ? new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : 'Sin fecha'

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="client-empty">{children}</p>
}

function riskFor(data: ClientData, scan: Scan | null): Risk | null {
  return scan ? data.risks.find((risk) => risk.escaneo_id === scan.id) ?? null : null
}

function authorizationCoversDomain(scope: string, domain: string): boolean {
  const target = domain.trim().replace(/\.$/, '').toLowerCase()
  return scope.split(/[\s,;]+/).some((entry) => entry.replace(/^[()[\]{}<>"'.,]+|[()[\]{}<>"'.,]+$/g, '').toLowerCase() === target)
}

export default function ClientPortalPage() {
  const { profile } = useAuth()
  if (!profile?.organizacion_id) return null
  return <ClientPortalView key={profile.organizacion_id} organizationId={profile.organizacion_id} />
}

function ClientPortalView({ organizationId }: { organizationId: string }) {
  const { section } = useParams()
  const { profile } = useAuth()
  const activeSection = section && sections.has(section as DashboardSection) ? section as DashboardSection : 'resumen'
  const activeLabel = navigation.find((item) => item.section === activeSection)?.label ?? 'Resumen'
  const [data, setData] = useState<ClientData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [scanDialogOpen, setScanDialogOpen] = useState(false)
  const [authorizationId, setAuthorizationId] = useState('')
  const [scanBusy, setScanBusy] = useState(false)
  const [pendingScanId, setPendingScanId] = useState<string | null>(null)
  const [trackedScanId, setTrackedScanId] = useState<string | null>(null)
  const [polling, setPolling] = useState(false)
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [scanStatusError, setScanStatusError] = useState<string | null>(null)
  const [stopDialogOpen, setStopDialogOpen] = useState(false)
  const [stopBusy, setStopBusy] = useState(false)
  const riskUnavailableScanId = useRef<string | null>(null)
  const refreshData = () => { setLoading(true); setRefresh((value) => value + 1) }

  useEffect(() => { document.title = `BaxterSec · ${activeLabel}` }, [activeLabel])
  useEffect(() => {
    let active = true
    const timer = window.setTimeout(() => {
      void loadClientData(organizationId).then((snapshot) => {
        if (!active) return
        setData(snapshot)
        setError(null)
        setLoading(false)
        const activeScan = snapshot.scans.find((scan) => scan.estado === 'ejecutando')
        if (activeScan) {
          setTrackedScanId(activeScan.id)
          setPolling(true)
        } else if (snapshot.latestFinishedScan && snapshot.latestFinishedScan.id !== riskUnavailableScanId.current && !snapshot.risks.some((risk) => risk.escaneo_id === snapshot.latestFinishedScan?.id)) {
          setTrackedScanId(snapshot.latestFinishedScan.id)
          setPolling(true)
        }
      }).catch((cause: unknown) => {
        if (!active) return
        setError(cause instanceof Error ? cause.message : 'No se pudo cargar el portal.')
        setLoading(false)
      })
    }, 0)
    return () => { active = false; window.clearTimeout(timer) }
  }, [organizationId, refresh])

  useEffect(() => {
    if (!polling || !trackedScanId) return
    let active = true
    let inFlight = false
    let consecutiveFailures = 0
    let riskPendingChecks = 0
    const check = async () => {
      if (inFlight) return
      inFlight = true
      try {
        const progress = await getScanProgress(trackedScanId)
        if (!active) return
        consecutiveFailures = 0
        setScanStatusError(null)
        setScanProgress(progress)
        if (progress.estado !== 'pendiente' && progress.estado !== 'ejecutando' && progress.estado !== 'cancelado' && !progress.riesgo) {
          riskPendingChecks += 1
          if (riskPendingChecks < 12) return
          riskUnavailableScanId.current = progress.escaneo_id
          setScanStatusError('El análisis terminó, pero el Risk Score aún no está disponible. Revisa el estado del backend o recalcula el riesgo.')
        }
        if (progress.estado !== 'pendiente' && progress.estado !== 'ejecutando') {
          setPolling(false)
          setTrackedScanId(null)
          refreshData()
        }
      } catch (cause) {
        if (!active) return
        if (!(cause instanceof ScanRequestError && cause.retryable)) {
          setPolling(false)
          setScanStatusError(null)
          setScanError(cause instanceof Error ? cause.message : 'No se pudo consultar el análisis.')
          return
        }
        consecutiveFailures += 1
        if (consecutiveFailures >= 3) {
          setScanStatusError('No se pudo consultar el estado del análisis. Reintentando automáticamente…')
        }
      } finally {
        inFlight = false
      }
    }
    void check()
    const timer = window.setInterval(() => { void check() }, 5000)
    return () => { active = false; window.clearInterval(timer) }
  }, [polling, trackedScanId])

  const canLaunch = profile?.rol === 'admin' || profile?.rol === 'analista'
  async function resolveCurrentFinding(findingId: string) {
    const scanId = data?.latestFinishedScan?.id
    if (!scanId) throw new Error('No hay un análisis finalizado para actualizar.')
    await resolveFinding(scanId, findingId)
    refreshData()
  }
  const validAuthorizations = data?.authorizations.filter((authorization) =>
    !authorization.revocada_en &&
    (!authorization.expira_en || new Date(authorization.expira_en).getTime() > data.loadedAt) &&
    authorizationCoversDomain(authorization.alcance, data.organization.dominio_principal)
  ) ?? []
  const runningScan = data?.scans.find((scan) => scan.estado === 'ejecutando')
  const runningId = trackedScanId ?? runningScan?.id
  const progressForRunning = scanProgress && (!runningId || scanProgress.escaneo_id === runningId) ? scanProgress : null
  const canStopRunning = profile?.rol === 'admin' || (profile?.rol === 'analista' && (runningScan?.solicitado_por === profile.id || (!runningScan && Boolean(trackedScanId))))

  async function stopAnalysis() {
    const scanId = progressForRunning?.escaneo_id ?? runningId
    if (!scanId || stopBusy) return
    setStopBusy(true)
    setScanError(null)
    try {
      const progress = await stopScan(scanId)
      setScanProgress(progress)
      setPolling(false)
      setTrackedScanId(null)
      setScanStatusError(null)
      setStopDialogOpen(false)
      refreshData()
    } catch (cause) {
      setStopDialogOpen(false)
      setScanError(cause instanceof Error ? cause.message : 'No se pudo detener el análisis.')
      try {
        const progress = await getScanProgress(scanId)
        setScanProgress(progress)
        if (progress.estado !== 'ejecutando') {
          setPolling(false)
          setTrackedScanId(null)
          refreshData()
        }
      } catch { /* Se conserva el error original. */ }
    } finally {
      setStopBusy(false)
    }
  }

  async function launchAnalysis() {
    if (!authorizationId || scanBusy) return
    setScanBusy(true)
    setScanError(null)
    let scanId = pendingScanId
    try {
      if (!scanId) {
        const created = await createScan(authorizationId)
        scanId = created.escaneo_id
        setPendingScanId(scanId)
      }
      const progress = await executeScan(scanId)
      setPendingScanId(null)
      setTrackedScanId(scanId)
      setScanProgress(progress)
      setPolling(true)
      setScanStatusError(null)
      setScanDialogOpen(false)
      refreshData()
    } catch (cause) {
      if (scanId) {
        try {
          const progress = await getScanProgress(scanId)
          if (progress.estado !== 'pendiente') {
            setPendingScanId(null)
            setTrackedScanId(scanId)
            setScanProgress(progress)
            setPolling(progress.estado === 'ejecutando')
            setScanDialogOpen(false)
            refreshData()
            return
          }
        } catch { /* El mensaje original explica el fallo; se conserva el ID para reintentar. */ }
      }
      setScanError(cause instanceof Error ? cause.message : 'No se pudo iniciar el análisis.')
    } finally {
      setScanBusy(false)
    }
  }

  const latest = data?.latestFinishedScan ?? null
  return <div className="dashboard-shell proposal-dashboard client-portal live-dashboard">
    <DashboardSidebar />
    <div className="dashboard-main">
      <DashboardHeader organizationName={data?.organization.nombre ?? 'PORTAL DE CLIENTE'} domain={data?.organization.dominio_principal ?? 'Cargando organización…'} domainVerified={validAuthorizations.length > 0} lastAnalysis={latest ? dateTime(latest.finalizado_en) : 'sin análisis'} actionLabel={canLaunch ? 'Nuevo análisis' : 'Actualizar'} actionDisabled={canLaunch && (loading || scanBusy || Boolean(runningScan) || polling)} onNewAnalysis={canLaunch ? () => { setAuthorizationId(validAuthorizations[0]?.id ?? ''); setScanError(null); setScanDialogOpen(true) } : refreshData} showAction={activeSection === 'analisis'} />
      <main className={`dashboard-content client-content${activeSection === 'relaciones' ? ' relations-content' : ''}${activeSection === 'fuentes' ? ' sources-content' : ''}${activeSection === 'hallazgos' ? ' findings-content' : ''}${activeSection === 'historial' ? ' history-content' : ''}`}>
        {activeSection === 'analisis' && (progressForRunning?.estado === 'ejecutando'
          ? <ScanProgressPanel progress={progressForRunning} canStop={Boolean(canStopRunning && progressForRunning.puede_detener)} stopping={stopBusy} onStop={() => setStopDialogOpen(true)} />
          : ((runningId && !progressForRunning) || scanProgress) && <div className="client-scan-notice" role="status"><strong>Análisis {scanProgress?.estado ?? 'ejecutando'}</strong><span>{polling && scanProgress?.finalizado_en && !scanProgress.riesgo && scanProgress.estado !== 'cancelado' ? 'Guardando hallazgos y calculando el Risk Score…' : scanProgress?.mensaje || 'Consultando el estado de las fuentes OSINT…'}</span></div>)}
        {scanError && !scanDialogOpen && <div className="client-error" role="alert">{scanError}</div>}
        {scanStatusError && <div className="client-error" role="alert">{scanStatusError}</div>}
        {(activeSection === 'analisis' || activeSection === 'fuentes' || activeSection === 'hallazgos' || activeSection === 'historial' || activeSection === 'configuracion') && <h1 className="sr-only">{activeLabel}</h1>}
        {activeSection === 'asistente' && <div className="content-intro proposal-section-intro"><div><span className="eyebrow">{data?.organization.dominio_principal ?? 'ORGANIZACIÓN'}</span><h1 className="sr-only">{activeLabel}</h1><p>Información de {data?.organization.nombre ?? 'tu organización'}</p></div></div>}
        {loading && <p className="client-loading" role="status">Cargando información de tu organización…</p>}
        {error && <div className="client-error" role="alert">{error}</div>}
        {!loading && data && <div className="dashboard-view" key={activeSection}><ClientSection section={activeSection} data={data} latest={latest} onResolve={canLaunch ? resolveCurrentFinding : undefined} /></div>}
      </main>
    </div>
    {scanDialogOpen && <div className="client-scan-backdrop" role="presentation"><section className="client-scan-dialog" role="dialog" aria-modal="true" aria-labelledby="client-scan-title"><h2 id="client-scan-title">Nuevo análisis</h2><p>Fuentes OSINT y validación Web · puertos 80/443</p><div className="client-scan-domain"><span>DOMINIO PRINCIPAL</span><strong>{data?.organization.dominio_principal}</strong></div>{validAuthorizations.length ? <label>Autorización vigente<select value={authorizationId} onChange={(event) => setAuthorizationId(event.target.value)} disabled={scanBusy || Boolean(pendingScanId)}>{validAuthorizations.map((authorization) => <option key={authorization.id} value={authorization.id}>{authorization.alcance}{authorization.expira_en ? ` · vence ${dateTime(authorization.expira_en)}` : ''}</option>)}</select></label> : <p className="client-scan-warning">No hay una autorización vigente que incluya exactamente este dominio. Regístrala antes de iniciar el análisis.</p>}{scanError && <div className="client-error" role="alert">{scanError}{pendingScanId && <p>El análisis se creó; puedes intentar iniciarlo de nuevo.</p>}</div>}<div className="client-scan-actions"><button type="button" onClick={() => { setScanDialogOpen(false) }} disabled={scanBusy}>Cancelar</button><button type="button" className="client-scan-primary" onClick={() => void launchAnalysis()} disabled={scanBusy || !authorizationId}>{scanBusy ? 'Iniciando…' : pendingScanId ? 'Reintentar inicio' : 'Iniciar análisis'}</button></div></section></div>}
    {stopDialogOpen && <div className="client-scan-backdrop" role="presentation"><section className="client-scan-dialog" role="alertdialog" aria-modal="true" aria-labelledby="client-stop-title" aria-describedby="client-stop-description"><h2 id="client-stop-title">¿Detener este análisis?</h2><p id="client-stop-description">Se conservarán las fuentes que ya terminaron. Las fuentes activas se detendrán y el análisis aparecerá como cancelado en el historial.</p><div className="client-scan-actions"><button type="button" onClick={() => setStopDialogOpen(false)} disabled={stopBusy}>Continuar análisis</button><button type="button" className="client-stop-confirm" onClick={() => void stopAnalysis()} disabled={stopBusy}>{stopBusy ? 'Deteniendo…' : 'Sí, detener'}</button></div></section></div>}
  </div>
}

function ClientSection({ section, data, latest, onResolve }: { section: DashboardSection; data: ClientData; latest: Scan | null; onResolve?: (findingId: string) => Promise<void> }) {
  switch (section) {
    case 'resumen': return <Summary data={data} latest={latest} />
    case 'analisis': return <AnalysisReport data={data} />
    case 'activos': return <AssetsScreen data={data} />
    case 'relaciones': return <RelationsScreen data={data} />
    case 'fuentes': return <LiveSourcesScreen data={data} />
    case 'hallazgos': return <FindingsScreen data={data} onResolve={onResolve} />
    case 'historial': return <HistoryScreen data={data} />
    case 'asistente': return <AssistantScreen data={data} />
    case 'configuracion': return <ClientSettings data={data} />
  }
}

function Summary({ data, latest }: { data: ClientData; latest: Scan | null }) {
  const risk = riskFor(data, latest)
  const formatScore = (value: number | null | undefined) => value == null ? '—' : value > 0 && value < 0.1 ? '<0.1' : value.toFixed(1)
  const confirmedRisk = risk?.cobertura?.riesgo_confirmado ?? risk
  const confirmedScore = confirmedRisk?.puntaje_global
  const priorityFindings = liveFindings(data).filter((finding) => finding.status !== 'Resuelto')
  const categories = confirmedRisk ? [
    ['Infraestructura', confirmedRisk.infraestructura],
    ['Identidad digital', confirmedRisk.identidad_digital],
    ['Configuración', confirmedRisk.configuracion],
    ['Fuga de datos', confirmedRisk.fuga_de_datos],
  ] as const : []
  const severityLabels = ['crítico', 'alto', 'medio', 'bajo']
  const severityCounts = severityLabels.map((label, index) => ({ label, count: priorityFindings.filter((finding) => finding.severity === (['critical', 'high', 'medium', 'low'] as const)[index]).length }))
  const maxSeverity = Math.max(1, ...severityCounts.map((item) => item.count))
  const types = [...new Set(data.assets.map((asset) => asset.tipo))].map((label) => ({ label, count: data.assets.filter((asset) => asset.tipo === label).length })).slice(0, 5)
  const maxType = Math.max(1, ...types.map((item) => item.count))
  const sourceResults = new Map(data.sourceResults.map((result) => [result.fuente_id, result]))
  const activeSources = scanSources(data)
  const enabledSources = activeSources.filter((source) => !isDisabledSourceResult(sourceResults.get(source.id)))
  const consulted = enabledSources.filter((source) => sourceResults.get(source.id)?.estado === 'completado' && !sourceResults.get(source.id)?.error).length
  const coverage = enabledSources.length ? Math.round(consulted / enabledSources.length * 100) : 0
  const sourceState = (sourceId: string) => {
    const result = sourceResults.get(sourceId)
    if (!result) return 'Sin ejecutar'
    if (isDisabledSourceResult(result)) return 'Deshabilitada'
    if (result.estado === 'completado') return result.error ? 'Parcial' : 'Saludable'
    if (result.estado === 'fallido') return 'Fallida'
    return result.estado === 'ejecutando' ? 'Ejecutando' : 'Sin ejecutar'
  }
  const historicalScans = liveHistoryScans(data)
  return <div className="overview-screen live-overview">
    <h2 className="sr-only">Resumen de exposición de {data.organization.nombre}</h2>
    <div className="overview-primary-grid">
      <section className="content-card proposal-card risk-card">
        <div className="card-heading"><div className="portal-info-heading"><h3>RISK SCORE CONFIRMADO</h3><InfoTip label="Risk Score" text="Puntaje confirmado del último análisis. La marca parcial indica que alguna comprobación no terminó correctamente." /></div><span>0–100</span></div>
        <div className="risk-card-body">
          <div className="proposal-score-ring" style={{ background: `conic-gradient(var(--teal) 0 ${confirmedScore ?? 0}%, var(--theme-track) ${confirmedScore ?? 0}% 100%)` }} aria-label={risk ? `Risk Score confirmado: ${formatScore(confirmedScore)} de 100` : 'Sin Risk Score confirmado'}><div><strong>{formatScore(confirmedScore)}</strong><span>{risk?.es_parcial ? 'PARCIAL' : risk ? 'CONFIRMADO' : 'SIN DATOS'}</span></div></div>
          <div className="risk-breakdown">{risk ? categories.map(([label, value]) => <div className="factor-row" key={label}><span className="factor-dot" /><span>{label}</span><strong>{formatScore(value)}</strong></div>) : <p className="client-empty">El puntaje aparecerá al terminar un análisis.</p>}</div>
        </div>
      </section>
      <section className="content-card proposal-card analysis-summary"><div className="card-heading"><div><h3>RESUMEN DE LA ORGANIZACIÓN</h3><small>{latest ? `Finalizado: ${dateTime(latest.finalizado_en)}` : 'Todavía no hay un análisis terminado.'}</small></div><span className="card-state">{latest?.estado ?? 'Pendiente'}</span></div><div className="summary-numbers"><div><strong>{data.assetCount}</strong><span>Activos en inventario</span></div><div><strong>{data.findingCount}</strong><span>Hallazgos del último análisis</span></div><div><strong>{severityCounts[0].count}</strong><span>Críticos del último análisis</span></div><div><strong>{data.scanCount}</strong><span>Análisis</span></div></div><div className="summary-highlights"><div><strong>{data.findings.filter((item) => item.estado === 'abierto').length}</strong><span>Hallazgos abiertos del último análisis</span></div><div><strong>{data.observations.length}</strong><span>Observaciones del último análisis</span></div><div><strong>{consulted}</strong><span>Fuentes completadas</span></div></div></section>
    </div>
    <div className="overview-analysis-grid">
      <RiskTrendChart actualScans={historicalScans} />
      <section className="content-card proposal-card severity-card"><div className="card-heading"><h3>HALLAZGOS POR SEVERIDAD</h3><Link to="/home/hallazgos">Ver todos</Link></div><div className="severity-bars">{severityCounts.map(({ label, count }) => <div className="severity-bar-row" key={label}><span>{label}</span><div className="bar-track"><i className={`tone-${label === 'crítico' ? 'critical' : label === 'alto' ? 'high' : label === 'medio' ? 'medium' : 'low'}`} style={{ width: `${count / maxSeverity * 100}%` }} /></div><strong>{count}</strong></div>)}</div></section>
    </div>
    <section className="content-card proposal-card priorities-card"><div className="card-heading"><h3>HALLAZGOS PRIORITARIOS</h3><Link to="/home/hallazgos">Ver todos los hallazgos</Link></div>{priorityFindings.length ? <div className="priority-table-wrap"><table className="priority-table"><thead><tr><th>SEVERIDAD</th><th>HALLAZGO</th><th>ACTIVO</th><th>CONFIANZA</th><th /></tr></thead><tbody>{priorityFindings.slice(0, 5).map((finding) => <tr key={finding.id}><td><span className={`priority-severity ${finding.severity === 'critical' ? 'critical' : 'high'}`}>{finding.severity === 'critical' ? 'CRÍTICA' : finding.severity === 'high' ? 'ALTA' : finding.severity === 'medium' ? 'MEDIA' : 'BAJA'}</span></td><td><strong>{finding.title}</strong><small className={`priority-evidence ${finding.evidenceLevel ?? 'sin_clasificar'}`}>{finding.evidenceLevel === 'confirmada' ? 'Confirmada' : finding.evidenceLevel === 'potencial' ? 'Potencial' : 'Sin clasificar'}</small></td><td>{finding.asset}</td><td>{finding.confidence}%</td><td><Link to="/home/hallazgos">Ver</Link></td></tr>)}</tbody></table></div> : <Empty>No hay hallazgos registrados.</Empty>}</section>
    <div className="overview-bottom-grid"><section className="content-card proposal-card inventory-card"><div className="card-heading"><h3>INVENTARIO DE ACTIVOS</h3><Link to="/home/activos">Explorar activos</Link></div>{types.length ? <div className="inventory-bars">{types.map(({ label, count }) => <div className="inventory-bar-row" key={label}><span>{label}</span><strong>{count}</strong><div className="bar-track"><i className="tone-info" style={{ width: `${count / maxType * 100}%` }} /></div></div>)}</div> : <Empty>Aún no hay activos descubiertos.</Empty>}</section><section className="content-card proposal-card sources-card"><div className="card-heading"><div className="portal-info-heading"><h3>SALUD DE FUENTES</h3><InfoTip label="salud de fuentes" text="Estado de las fuentes habilitadas en el último análisis. Los fallos y resultados parciales reducen la cobertura." /></div><Link to="/home/fuentes">Detalles</Link></div><div className="source-health-list">{activeSources.map((source) => { const result = sourceResults.get(source.id); const status = !result || isDisabledSourceResult(result) || result.estado === 'pendiente' ? 'disabled' : result.estado === 'fallido' ? 'error' : result.estado === 'completado' ? result.error ? 'partial' : 'healthy' : 'running'; return <div className={`source-health-row ${status}`} key={source.id}><span className="source-status-dot" /><strong>{source.nombre}</strong><em>{sourceState(source.id)}</em></div> })}</div><div className="sources-foot"><span>Fuentes habilitadas saludables</span><strong>{coverage}%</strong></div><div className="source-progress" role="img" aria-label={`Fuentes habilitadas saludables: ${coverage}%`}><i style={{ width: `${coverage}%` }} /></div></section></div>
    <section className="content-card proposal-card changes-card"><div className="card-heading"><h3>ACTIVIDAD RECIENTE</h3><Link to="/home/historial">Abrir historial</Link></div>{data.scans.length ? <div className="milestone-grid">{data.scans.slice(0, 4).map((scan) => <div className="milestone" key={scan.id}><span className="milestone-ring tone-info" /><div><strong>Análisis {scan.estado}</strong><p>{dateTime(scan.finalizado_en ?? scan.iniciado_en)}</p><small>{riskFor(data, scan)?.puntaje_global ?? '—'} puntos de riesgo</small></div></div>)}</div> : <Empty>Todavía no hay análisis registrados.</Empty>}</section>
  </div>
}

function ClientSettings({ data }: { data: ClientData }) {
  const { profile } = useAuth()
  return <div className="client-section client-settings-layout">
    <header className="settings-page-heading"><span className="eyebrow">PREFERENCIAS Y ALCANCE</span><InfoTip label="configuración" text="Consulta el contexto de tu organización y ajusta la apariencia del portal." /></header>
    <div className="settings-primary-grid"><SettingsScreen />
      <section className="content-card simple-section settings-card" aria-labelledby="organization-settings-title"><div className="eyebrow">CUENTA Y ORGANIZACIÓN</div><div className="portal-info-heading"><h2 id="organization-settings-title">Mi organización</h2><InfoTip label="mi organización" text="Datos de la sesión y del dominio principal." /></div><dl className="client-settings-facts"><div><dt>Nombre</dt><dd>{data.organization.nombre}</dd></div><div><dt>Dominio principal</dt><dd>{data.organization.dominio_principal}</dd></div><div><dt>Mi cuenta</dt><dd>{profile?.correo ?? '—'}</dd></div><div><dt>Mi rol</dt><dd>{profile?.rol ?? '—'}</dd></div></dl></section>
    </div>
    <section className="content-card simple-section settings-card" aria-labelledby="authorizations-title"><div className="eyebrow">ALCANCE AUTORIZADO</div><div className="portal-info-heading"><h2 id="authorizations-title">Autorizaciones de dominio</h2><InfoTip label="autorizaciones de dominio" text="Permisos registrados para ejecutar análisis sobre dominios específicos." /></div>{data.authorizations.length ? <div className="client-table-wrap"><table><thead><tr><th>Alcance</th><th>Estado</th><th>Expira</th></tr></thead><tbody>{data.authorizations.map((authorization) => <tr key={authorization.id}><td><strong>{authorization.alcance}</strong></td><td><span className={`settings-status ${authorization.revocada_en ? 'inactive' : authorization.expira_en && new Date(authorization.expira_en).getTime() < data.loadedAt ? 'expired' : 'active'}`}>{authorization.revocada_en ? 'Revocada' : authorization.expira_en && new Date(authorization.expira_en).getTime() < data.loadedAt ? 'Vencida' : 'Vigente'}</span></td><td>{dateTime(authorization.expira_en)}</td></tr>)}</tbody></table></div> : <Empty>No hay autorizaciones registradas.</Empty>}</section>
  </div>
}
