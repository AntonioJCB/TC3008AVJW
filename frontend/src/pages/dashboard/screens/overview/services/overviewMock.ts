import { demoProject } from '../../../services/demoData'

// Valores ilustrativos para reproducir la propuesta visual; no son ejecuciones reales.
export const riskFactors = [
  { label: 'Infraestructura', value: 30, color: 'var(--risk-high)' },
  { label: 'Exposición', value: 21, color: 'var(--bronze)' },
  { label: 'Identidad', value: 14, color: 'var(--teal)' },
  { label: 'Configuración', value: 10, color: 'var(--risk-critical)' },
]

export const riskTrends = {
  '7D': [65, 67, 69, 75],
  '30D': [42, 48, 55, 63, 75],
  '90D': [36, 43, 47, 58, 63, 75],
  Todo: [28, 36, 42, 48, 55, 63, 75],
} as const
export type TrendRange = keyof typeof riskTrends

export const severitySummary = [
  { label: 'Crítico', count: demoProject.findings.filter((item) => item.severity === 'Crítico').length, tone: 'critical' },
  { label: 'Alto', count: 0, tone: 'high' },
  { label: 'Medio', count: demoProject.findings.filter((item) => item.severity === 'Medio').length, tone: 'medium' },
  { label: 'Bajo', count: 0, tone: 'low' },
  { label: 'Info', count: 0, tone: 'info' },
] as const

export const inventorySummary = [
  { label: 'Subdominios', count: demoProject.assets.filter((item) => item.kind === 'Subdominio').length, tone: 'reed' },
  { label: 'IPs públicas', count: demoProject.assets.filter((item) => item.kind === 'IP pública').length, tone: 'sue' },
  { label: 'Correos', count: demoProject.assets.filter((item) => item.kind === 'Correo').length, tone: 'bronze' },
  { label: 'Puertos', count: demoProject.assets.filter((item) => item.kind === 'Puerto').length, tone: 'johnny' },
] as const

export const recentMilestones = [
  { title: 'Escenario preparado', detail: 'Innovatech Solutions Ltd.', step: 'Paso 1', tone: 'sue' },
  { title: 'Activos de muestra', detail: `${demoProject.assets.length} registros ficticios`, step: 'Paso 2', tone: 'reed' },
  { title: 'Hallazgos de muestra', detail: `${demoProject.findings.length} casos ilustrativos`, step: 'Paso 3', tone: 'bronze' },
  { title: 'Resumen disponible', detail: 'Sin ejecución de escaneo', step: 'Paso 4', tone: 'low' },
] as const
