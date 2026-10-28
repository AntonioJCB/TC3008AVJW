// Datos estáticos de la propuesta visual. No provienen de un escaneo.
export type AssetKind = 'Dominio' | 'Subdominio' | 'IP pública' | 'Correo'
export type AssetExposure = 'Crítica' | 'Alta' | 'Media' | 'Baja'
export type AssetFilter = AssetKind | 'Todos'

export interface AssetRecord {
  id: string
  kind: AssetKind
  value: string
  detail: string
  exposure: AssetExposure
  findings: number
  sources: string[]
  observed: string
  observationState: string
  isNew: boolean
  confidence: number
  description: string
}

export const assetFilters: { label: string; kind: AssetFilter }[] = [
  { label: 'Todos', kind: 'Todos' },
  { label: 'Dominios', kind: 'Dominio' },
  { label: 'Subdominios', kind: 'Subdominio' },
  { label: 'IPs', kind: 'IP pública' },
  { label: 'Correos', kind: 'Correo' },
]

export const sampleAssets: AssetRecord[] = [
  {
    id: 'admin', kind: 'Subdominio', value: 'admin.empresa.com', detail: 'Resuelve a 189.203.•••.••',
    exposure: 'Crítica', findings: 2, sources: ['crt.sh', 'Shodan'], observed: 'Hace 4 min',
    observationState: 'Nuevo', isNew: true, confidence: 96,
    description: 'Activo nuevo correlacionado por certificado, resolución DNS y observación de servicio.',
  },
  {
    id: 'dev', kind: 'Subdominio', value: 'dev.empresa.com', detail: 'Entorno de desarrollo',
    exposure: 'Crítica', findings: 1, sources: ['SpiderFoot', 'Shodan'], observed: 'Hace 21 min',
    observationState: 'Nuevo', isNew: true, confidence: 93,
    description: 'Entorno de desarrollo público relacionado con servicios observados en la muestra.',
  },
  {
    id: 'ip', kind: 'IP pública', value: '189.203.•••.••', detail: '3 servicios observados',
    exposure: 'Alta', findings: 2, sources: ['Shodan', 'DNS'], observed: 'Hoy, 10:29',
    observationState: 'Confirmado', isNew: false, confidence: 91,
    description: 'Dirección pública vinculada a subdominios y servicios del escenario de ejemplo.',
  },
  {
    id: 'domain', kind: 'Dominio', value: 'empresa.com', detail: 'Dominio raíz autorizado',
    exposure: 'Media', findings: 1, sources: ['crt.sh', 'DNS', 'SpiderFoot'], observed: 'Hoy, 10:32',
    observationState: 'Monitoreado', isNew: false, confidence: 99,
    description: 'Dominio raíz utilizado para agrupar los activos y relaciones de esta maqueta.',
  },
  {
    id: 'email', kind: 'Correo', value: 'ops@empresa.com', detail: 'Cuenta operativa',
    exposure: 'Alta', findings: 1, sources: ['theHarvester'], observed: 'Hoy, 10:14',
    observationState: 'Confirmado', isNew: false, confidence: 88,
    description: 'Cuenta corporativa indexada en una fuente pública del escenario ilustrativo.',
  },
  {
    id: 'api', kind: 'Subdominio', value: 'api.empresa.com', detail: 'API pública · TLS activo',
    exposure: 'Media', findings: 1, sources: ['crt.sh', 'SpiderFoot'], observed: 'Hace 2 h',
    observationState: 'Actualizado', isNew: false, confidence: 95,
    description: 'Servicio de API identificado por certificado y fuentes de descubrimiento.',
  },
  {
    id: 'www', kind: 'Subdominio', value: 'www.empresa.com', detail: 'Sitio corporativo',
    exposure: 'Baja', findings: 0, sources: ['crt.sh', 'DNS'], observed: 'Hoy, 09:58',
    observationState: 'Confirmado', isNew: false, confidence: 97,
    description: 'Sitio público corporativo sin hallazgos asociados en esta muestra.',
  },
]

// El inventario completo permite que filtros, paginación y KPI compartan una sola fuente.
const extraDomains = ['empresa.net', 'empresa.org', 'empresa.mx']
const extraSubdomains = ['mail', 'vpn', 'portal', 'status', 'docs', 'cdn', 'staging', 'soporte']
const extraIps = ['203.0.113.41', '203.0.113.42', '203.0.113.44', '203.0.113.45', '203.0.113.46', '203.0.113.47', '203.0.113.48']
const extraMailboxes = [
  'contacto', 'soporte', 'seguridad', 'ventas', 'facturacion', 'administracion',
  'infraestructura', 'desarrollo', 'recursos.humanos', 'comunicacion', 'legal',
  'compras', 'direccion', 'noc', 'soc', 'privacidad', 'alianzas', 'producto',
  'monitoreo', 'reportes', 'servicios', 'alertas',
]

const mockRecord = (kind: AssetKind, value: string, index: number, isNew = false): AssetRecord => ({
  id: `extra-${kind}-${index}`,
  kind,
  value,
  detail: kind === 'Dominio' ? 'Dominio relacionado' : kind === 'Subdominio' ? 'Servicio público observado' : kind === 'IP pública' ? 'Dirección pública relacionada' : 'Cuenta corporativa observada',
  exposure: 'Baja',
  findings: 0,
  sources: kind === 'Correo' ? ['theHarvester'] : kind === 'IP pública' ? ['Shodan', 'DNS'] : ['crt.sh', 'DNS'],
  observed: 'Hoy, 09:40',
  observationState: isNew ? 'Nuevo' : 'Confirmado',
  isNew,
  confidence: 89,
  description: 'Activo relacionado con el dominio de muestra en el inventario ilustrativo.',
})

export const mockAssets: AssetRecord[] = [
  ...sampleAssets,
  ...extraDomains.map((value, index) => mockRecord('Dominio', value, index)),
  ...extraSubdomains.map((name, index) => mockRecord('Subdominio', `${name}.empresa.com`, index, index < 4)),
  ...extraIps.map((value, index) => mockRecord('IP pública', value, index)),
  ...extraMailboxes.map((name, index) => mockRecord('Correo', `${name}@empresa.com`, index)),
]

export const assetStats = {
  total: mockAssets.length,
  subdomains: mockAssets.filter((asset) => asset.kind === 'Subdominio').length,
  publicIps: mockAssets.filter((asset) => asset.kind === 'IP pública').length,
  newAssets: mockAssets.filter((asset) => asset.isNew).length,
  associatedFindings: mockAssets.filter((asset) => asset.kind === 'Subdominio' && asset.findings > 0).length,
  mergedDuplicates: 31,
  observedServices: 5,
  rawRecords: 184,
  normalizedRecords: 78,
  coverage: 87,
} as const
