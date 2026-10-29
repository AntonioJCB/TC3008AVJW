// Escenario local de la propuesta visual. No representa análisis ejecutados.
export type HistoryKind = 'asset' | 'finding' | 'source' | 'scan'
export type HistoryFilter = HistoryKind | 'all'
export type HistoryRange = '7D' | '30D' | '90D'
export type HistoryTone = 'critical' | 'warning' | 'resolved' | 'neutral'

export interface HistoryEvent {
  id: string
  kind: HistoryKind
  date: string
  time: string
  title: string
  detail: string
  context: string
  contextDetail: string
  impact: string
  impactDetail: string
  impactTone: HistoryTone
  status: string
  followUp: boolean
  critical?: boolean
}

export interface HistoryScan {
  date: string
  score: number
  marker?: string
}

export const historyFilters: { kind: HistoryFilter; label: string }[] = [
  { kind: 'all', label: 'Todos' },
  { kind: 'asset', label: 'Activos' },
  { kind: 'finding', label: 'Hallazgos' },
  { kind: 'source', label: 'Fuentes' },
  { kind: 'scan', label: 'Análisis' },
]

export const historyScans: HistoryScan[] = [
  { date: '01 sep', score: 42 },
  { date: '08 sep', score: 48 },
  { date: '15 sep', score: 55 },
  { date: '22 sep', score: 60, marker: 'Servicio público' },
  { date: '27 sep', score: 63 },
  { date: 'Hoy', score: 72, marker: 'Panel administrativo' },
]

export const historyRanges: Record<HistoryRange, HistoryScan[]> = {
  '7D': historyScans.slice(-3),
  '30D': historyScans,
  '90D': [
    { date: '01 jul', score: 34 },
    { date: '20 jul', score: 38 },
    { date: '12 ago', score: 40 },
    ...historyScans,
  ],
}

export const historyEvents: HistoryEvent[] = [
  {
    id: 'new-dev', kind: 'asset', date: 'Hoy', time: '10:28', title: 'Nuevo subdominio descubierto', detail: 'dev.empresa.com',
    context: 'crt.sh · SpiderFoot', contextDetail: '2 fuentes correlacionadas', impact: '+15', impactDetail: 'Risk Score',
    impactTone: 'critical', status: 'Nuevo', followUp: true,
  },
  {
    id: 'public-admin', kind: 'finding', date: 'Hoy', time: '10:24', title: 'Panel administrativo expuesto', detail: 'admin.empresa.com',
    context: 'Shodan', contextDetail: 'Servicio HTTPS confirmado', impact: '+20', impactDetail: 'Impacto bruto',
    impactTone: 'critical', status: 'Nuevo', followUp: true, critical: true,
  },
  {
    id: 'shodan-partial', kind: 'source', date: 'Hoy', time: '10:17', title: 'Cobertura parcial de Shodan', detail: 'El análisis continuó con resultados disponibles',
    context: 'Shodan', contextDetail: 'Tiempo de espera agotado', impact: '—', impactDetail: 'Sin cambio',
    impactTone: 'neutral', status: 'Revisar', followUp: true,
  },
  {
    id: 'scan-complete', kind: 'scan', date: 'Hoy', time: '10:32', title: 'Análisis completado', detail: '47 activos · 11 hallazgos',
    context: 'Motor de análisis', contextDetail: '87% de cobertura', impact: '72', impactDetail: 'Score final',
    impactTone: 'neutral', status: 'Completado', followUp: false,
  },
  {
    id: 'cert-updated', kind: 'finding', date: '29 sep', time: '16:42', title: 'Certificado actualizado', detail: 'api.empresa.com',
    context: 'crt.sh', contextDetail: 'Nueva fecha de expiración', impact: '−10', impactDetail: 'Riesgo reducido',
    impactTone: 'resolved', status: 'Resuelto', followUp: false,
  },
  {
    id: 'new-ip', kind: 'asset', date: '27 sep', time: '08:09', title: 'Nueva IP pública observada', detail: '189.203.•••.••',
    context: 'DNS · Shodan', contextDetail: '3 servicios asociados', impact: '+6', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Confirmado', followUp: true,
  },
  {
    id: 'email-indexed', kind: 'finding', date: '24 sep', time: '12:31', title: 'Correo corporativo indexado', detail: 'ops@empresa.com',
    context: 'theHarvester', contextDetail: 'Fuente pública confirmada', impact: '+3', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Revisado', followUp: false,
  },
  {
    id: 'baseline', kind: 'scan', date: '01 sep', time: '09:00', title: 'Línea base creada', detail: 'Primer análisis autorizado',
    context: '4 fuentes OSINT', contextDetail: '42 activos iniciales', impact: '42', impactDetail: 'Score inicial',
    impactTone: 'neutral', status: 'Base', followUp: false,
  },
  {
    id: 'new-vpn', kind: 'asset', date: '29 sep', time: '13:10', title: 'Subdominio VPN observado', detail: 'vpn.empresa.com',
    context: 'crt.sh · DNS', contextDetail: 'Certificado y resolución coincidentes', impact: '+4', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Confirmado', followUp: true,
  },
  {
    id: 'new-staging', kind: 'asset', date: '28 sep', time: '11:05', title: 'Entorno de pruebas descubierto', detail: 'staging.empresa.com',
    context: 'SpiderFoot', contextDetail: 'Subdominio público observado', impact: '+5', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Revisar', followUp: true,
  },
  {
    id: 'new-mail', kind: 'asset', date: '26 sep', time: '09:18', title: 'Servidor de correo identificado', detail: 'mail.empresa.com',
    context: 'DNS · crt.sh', contextDetail: 'Registro MX y certificado', impact: '—', impactDetail: 'Sin cambio',
    impactTone: 'neutral', status: 'Confirmado', followUp: false,
  },
  {
    id: 'new-portal', kind: 'asset', date: '25 sep', time: '17:30', title: 'Portal público incorporado', detail: 'portal.empresa.com',
    context: 'SpiderFoot · DNS', contextDetail: 'Servicio asociado al dominio', impact: '+2', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Confirmado', followUp: false,
  },
  {
    id: 'public-legacy', kind: 'finding', date: '25 sep', time: '14:16', title: 'Servicio heredado accesible', detail: '189.203.•••.••:8080',
    context: 'Shodan', contextDetail: 'Puerto 8080 responde', impact: '+8', impactDetail: 'Impacto bruto',
    impactTone: 'warning', status: 'Nuevo', followUp: true,
  },
  {
    id: 'tls-watch', kind: 'finding', date: '24 sep', time: '10:11', title: 'Certificado TLS bajo seguimiento', detail: 'api.empresa.com',
    context: 'crt.sh', contextDetail: 'Vencimiento próximo', impact: '+2', impactDetail: 'Risk Score',
    impactTone: 'warning', status: 'Revisado', followUp: false,
  },
  {
    id: 'spiderfoot-delay', kind: 'source', date: '24 sep', time: '08:54', title: 'Demora en SpiderFoot', detail: 'Consulta completada con retraso',
    context: 'SpiderFoot', contextDetail: 'Tiempo de respuesta elevado', impact: '—', impactDetail: 'Sin cambio',
    impactTone: 'neutral', status: 'Revisar', followUp: true,
  },
]

const latestScan = historyScans.at(-1)!
const previousScan = historyScans.at(-2)!

export const historyStats = {
  currentScore: latestScan.score,
  previousScore: previousScan.score,
  scoreDelta: latestScan.score - previousScan.score,
  completedScans: historyScans.length,
  newAssets: historyEvents.filter((event) => event.kind === 'asset').length,
  relevantChanges: historyEvents.length,
  followUpChanges: historyEvents.filter((event) => event.followUp).length,
  newFindings: historyEvents.filter((event) => event.kind === 'finding' && event.status === 'Nuevo').length,
  newCritical: historyEvents.filter((event) => event.kind === 'finding' && event.status === 'Nuevo' && event.critical).length,
  resolved: historyEvents.filter((event) => event.status === 'Resuelto').length,
} as const
