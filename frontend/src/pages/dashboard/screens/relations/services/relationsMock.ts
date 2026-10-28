import { assetStats } from '../../assets/services/assetsMock'

// Escenario ilustrativo del mapa de exposición. No representa un análisis real.
export type RelationTone = 'domain' | 'service' | 'identity' | 'critical'

export interface RelationNode {
  id: string
  name: string
  badge: string
  kind: string
  caption: string
  impact: string
  description: string
  sources: string[]
  related: string
  tone: RelationTone
  x: number
  y: number
}

export interface RelationEdge {
  id: string
  from: string
  to: string
  critical?: boolean
}

export interface PriorityRoute {
  id: string
  title: string
  path: string
  impact: string
  nodeId: string
  edgeIds: string[]
}

// The board can grow with the number of entities without changing its zoom controls.
export const relationCanvas = { width: 1080, height: 450 }

export const relationNodes: RelationNode[] = [
  {
    id: 'root', name: 'empresa.com', badge: 'DOM', kind: 'Dominio raíz', caption: '12 conexiones', impact: '12 conexiones',
    description: 'Es el punto de mayor concentración: conecta subdominios, infraestructura e identidades observadas.',
    sources: ['crt.sh', 'DNS', 'SpiderFoot'], related: 'admin, dev, api, correo e IP', tone: 'domain', x: 50, y: 49,
  },
  {
    id: 'api', name: 'api.empresa.com', badge: 'SUB', kind: 'Subdominio', caption: 'Certificado activo', impact: 'Riesgo medio',
    description: 'API pública vinculada al dominio raíz y al certificado observado.',
    sources: ['crt.sh', 'DNS'], related: 'empresa.com · Certificado SAN', tone: 'domain', x: 22, y: 24,
  },
  {
    id: 'admin', name: 'admin.empresa.com', badge: 'ADM', kind: 'Servicio administrativo', caption: 'Acceso público', impact: 'Riesgo crítico · +20',
    description: 'Panel administrativo visible desde internet y asociado a una dirección pública.',
    sources: ['crt.sh', 'Shodan'], related: 'empresa.com · IP pública · HTTPS', tone: 'critical', x: 77, y: 21,
  },
  {
    id: 'ip', name: '189.203.•••.••', badge: 'IP', kind: 'IP pública', caption: '3 servicios', impact: 'Riesgo alto · +6',
    description: 'Infraestructura pública relacionada con el panel administrativo y otros servicios.',
    sources: ['Shodan', 'DNS'], related: 'admin.empresa.com · 3 servicios', tone: 'service', x: 85, y: 63,
  },
  {
    id: 'identity', name: 'ops@empresa.com', badge: 'ID', kind: 'Identidad', caption: 'Fuente pública', impact: 'Riesgo alto · +3',
    description: 'Cuenta corporativa indexada en una fuente pública y vinculada al dominio.',
    sources: ['theHarvester'], related: 'empresa.com · 1 hallazgo', tone: 'identity', x: 56, y: 83,
  },
  {
    id: 'dev', name: 'dev.empresa.com', badge: 'DEV', kind: 'Entorno de desarrollo', caption: 'Activo nuevo', impact: 'Riesgo crítico · +15',
    description: 'Entorno de desarrollo público conectado al dominio y a un servicio observado.',
    sources: ['SpiderFoot', 'Shodan'], related: 'empresa.com · servicio 8080', tone: 'domain', x: 18, y: 73,
  },
  {
    id: 'cert', name: 'Certificado SAN', badge: 'TLS', kind: 'Certificado', caption: '2 dominios', impact: 'Sin impacto directo',
    description: 'El certificado permite relacionar el dominio raíz con la API pública.',
    sources: ['crt.sh'], related: 'empresa.com · api.empresa.com', tone: 'service', x: 14, y: 49,
  },
]

export const relationEdges: RelationEdge[] = [
  { id: 'root-api', from: 'root', to: 'api' },
  { id: 'root-admin', from: 'root', to: 'admin', critical: true },
  { id: 'root-ip', from: 'root', to: 'ip' },
  { id: 'root-identity', from: 'root', to: 'identity' },
  { id: 'root-dev', from: 'root', to: 'dev' },
  { id: 'api-cert', from: 'api', to: 'cert' },
  { id: 'admin-ip', from: 'admin', to: 'ip', critical: true },
]

export const priorityRoutes: PriorityRoute[] = [
  { id: 'admin', title: 'Administración pública', path: 'Dominio → panel → IP', impact: '+20 puntos', nodeId: 'admin', edgeIds: ['root-admin', 'admin-ip'] },
  { id: 'dev', title: 'Desarrollo expuesto', path: 'Dominio → entorno → servicio', impact: '+15 puntos', nodeId: 'dev', edgeIds: ['root-dev'] },
  { id: 'identity', title: 'Identidad indexada', path: 'Dominio → correo → fuente', impact: '+3 puntos', nodeId: 'identity', edgeIds: ['root-identity'] },
  { id: 'service', title: 'Servicio público', path: 'Dominio → IP → servicios', impact: '+6 puntos', nodeId: 'ip', edgeIds: ['root-ip'] },
]

export const relationStats = {
  connections: 63,
  connectedAssets: 31,
  isolatedAssets: assetStats.total - 31,
  concentration: 12,
}
