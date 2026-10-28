// Escenario visual estático del mockup. No representa ejecuciones reales.
export const overviewSnapshot = {
  score: 72,
  assetCount: 47,
  findingCount: 11,
  criticalCount: 3,
  newAssetCount: 6,
  processedRecords: 184,
  sourceCoverage: 87,
} as const

export const riskFactors = [
  { label: 'Infraestructura', value: 28, color: 'var(--theme-soft)' },
  { label: 'Exposición', value: 22, color: 'var(--bronze)' },
  { label: 'Identidad', value: 14, color: 'var(--theme-active)' },
  { label: 'Configuración', value: 8, color: 'var(--coral)' },
]

export const riskTrends = {
  '7D': [63, 66, 70, 72],
  '30D': [42, 48, 55, 63, 71, 72],
  '90D': [32, 38, 42, 48, 55, 63, 71, 72],
  Todo: [26, 32, 38, 42, 48, 55, 63, 71, 72],
} as const
export type TrendRange = keyof typeof riskTrends

export const severitySummary = [
  { label: 'Crítico', count: 3, tone: 'critical' },
  { label: 'Alto', count: 5, tone: 'high' },
  { label: 'Medio', count: 4, tone: 'medium' },
  { label: 'Bajo', count: 2, tone: 'low' },
  { label: 'Info', count: 1, tone: 'info' },
] as const

export const inventorySummary = [
  { label: 'Dominios', count: 4, tone: 'reed' },
  { label: 'Subdominios', count: 12, tone: 'reed' },
  { label: 'IPs públicas', count: 8, tone: 'bronze' },
  { label: 'Correos', count: 14, tone: 'sue' },
  { label: 'Certificados', count: 5, tone: 'johnny' },
  { label: 'Servicios', count: 9, tone: 'reed' },
] as const

export const priorityFindings = [
  { id: 'priority-1', severity: 'Crítico', title: 'Panel administrativo expuesto públicamente', asset: 'admin.empresa.com', confidence: 92 },
  { id: 'priority-2', severity: 'Alto', title: 'Servicio heredado accesible desde internet', asset: '189.203.•••.••', confidence: 87 },
  { id: 'priority-3', severity: 'Alto', title: 'Correo corporativo indexado en fuente pública', asset: 'ops@empresa.com', confidence: 81 },
] as const

export const sourceHealth = [
  { name: 'crt.sh', status: 'Saludable', tone: 'healthy' },
  { name: 'SpiderFoot', status: 'Saludable', tone: 'healthy' },
  { name: 'theHarvester', status: 'Saludable', tone: 'healthy' },
  { name: 'Shodan', status: 'Parcial', tone: 'partial' },
] as const

export const recentMilestones = [
  { title: 'Nuevo subdominio', detail: 'dev.empresa.com', step: 'Hace 4 min', tone: 'reed' },
  { title: 'Nuevo hallazgo', detail: 'Servicio de desarrollo público', step: 'Hace 21 min', tone: 'critical' },
  { title: 'Certificado actualizado', detail: 'api.empresa.com', step: 'Hace 2 h', tone: 'bronze' },
  { title: 'Análisis completado', detail: '4 fuentes · 184 registros', step: 'Hace 3 h', tone: 'low' },
] as const
