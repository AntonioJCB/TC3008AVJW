import { assetStats } from '../../assets/services/assetsMock'

// Datos locales de la propuesta visual. Las acciones de esta pantalla no consultan redes externas.
export type SourceStatus = 'healthy' | 'partial' | 'error'
export type SourceFilter = 'all' | 'healthy' | 'partial'

export interface SourceRecord {
  id: string
  name: string
  monogram: string
  type: string
  records: number
  contribution: string
  response: string
  lastConsulted: string
  status: SourceStatus
  coverage: number
  confidence: number
  services: number
  purpose: string
  description: string
}

export const mockSources: SourceRecord[] = [
  { id: 'crt', name: 'crt.sh', monogram: 'CR', type: 'Certificados · dominios', records: 46, contribution: '18 activos únicos', response: '1.2 s', lastConsulted: 'Hoy, 10:13', status: 'healthy', coverage: 100, confidence: 98, services: 0, purpose: 'Certificados y subdominios', description: 'Certificados públicos utilizados para descubrir dominios y subdominios relacionados.' },
  { id: 'spiderfoot', name: 'SpiderFoot', monogram: 'SF', type: 'Infraestructura · relaciones', records: 68, contribution: '24 activos únicos', response: '8.4 s', lastConsulted: 'Hoy, 10:14', status: 'healthy', coverage: 94, confidence: 93, services: 0, purpose: 'Correlación de infraestructura', description: 'Relaciona activos, infraestructura pública y evidencias entre fuentes.' },
  { id: 'harvester', name: 'theHarvester', monogram: 'TH', type: 'Correos · hosts', records: 39, contribution: '14 identidades', response: '5.8 s', lastConsulted: 'Hoy, 10:15', status: 'healthy', coverage: 92, confidence: 90, services: 0, purpose: 'Identidades y hosts públicos', description: 'Recopila identidades y hosts publicados en fuentes abiertas.' },
  { id: 'shodan', name: 'Shodan', monogram: 'SH', type: 'IPs · puertos · servicios', records: 31, contribution: '9 servicios', response: '12.0 s', lastConsulted: 'Tiempo agotado', status: 'partial', coverage: 74, confidence: 88, services: 9, purpose: 'Servicios expuestos e IPs', description: 'La fuente respondió con 31 registros antes de agotar el tiempo. El análisis continuó sin inventar resultados faltantes.' },
]

export const sourceStats = {
  connected: mockSources.length,
  healthy: mockSources.filter((source) => source.status === 'healthy').length,
  partial: mockSources.filter((source) => source.status === 'partial').length,
  coverage: 87,
  rawRecords: mockSources.reduce((total, source) => total + source.records, 0),
  normalized: assetStats.normalizedRecords,
  duplicates: assetStats.mergedDuplicates,
  assets: assetStats.total,
}

export const coverageByData = [
  { label: 'Dominios y TLS', value: 100 },
  { label: 'Infraestructura', value: 94 },
  { label: 'Identidades', value: 92 },
  { label: 'Servicios públicos', value: 74 },
] as const
