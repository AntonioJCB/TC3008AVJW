// Datos locales de la maqueta: cada contador se calcula desde esta lista.
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low'
export type FindingStatus = 'Nuevo' | 'Abierto' | 'Revisado' | 'Aceptado'
export type FindingFilter = FindingSeverity | 'all'

export interface FindingRecord {
  id: string
  title: string
  asset: string
  severity: FindingSeverity
  rule: string
  sources: string[]
  confidence: number
  status: FindingStatus
  description: string
  impact: number
  traceFinding: string
  traceEvidence: string
}

export const severityLabels: Record<FindingSeverity, string> = {
  critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo',
}

export const findingFilters: { value: FindingFilter; label: string }[] = [
  { value: 'all', label: 'Todos' },
  { value: 'critical', label: 'Críticos' },
  { value: 'high', label: 'Altos' },
  { value: 'medium', label: 'Medios' },
  { value: 'low', label: 'Bajos' },
]

export const mockFindings: FindingRecord[] = [
  {
    id: 'public-admin', title: 'Panel administrativo expuesto', asset: 'admin.empresa.com', severity: 'critical',
    rule: 'PUBLIC_ADMIN_SERVICE', sources: ['crt.sh', 'Shodan'], confidence: 92, status: 'Nuevo',
    description: 'El activo acepta conexiones públicas y coincide con una regla de acceso administrativo.',
    impact: 20, traceFinding: 'Panel público', traceEvidence: 'Puerto 443 · título detectado',
  },
  {
    id: 'public-dev', title: 'Entorno de desarrollo accesible', asset: 'dev.empresa.com', severity: 'critical',
    rule: 'PUBLIC_DEV_ENV', sources: ['SpiderFoot', 'Shodan'], confidence: 90, status: 'Nuevo',
    description: 'Un entorno de desarrollo responde desde internet y expone servicios que requieren revisión.',
    impact: 18, traceFinding: 'Entorno público', traceEvidence: 'Servicio DEV · acceso externo',
  },
  {
    id: 'legacy-service', title: 'Servicio heredado expuesto', asset: '189.203.•••.••:8080', severity: 'high',
    rule: 'LEGACY_PUBLIC_SERVICE', sources: ['Shodan', 'SpiderFoot'], confidence: 87, status: 'Abierto',
    description: 'Un servicio heredado continúa accesible desde la IP pública observada.',
    impact: 12, traceFinding: 'Servicio público', traceEvidence: 'Puerto 8080 · banner detectado',
  },
  {
    id: 'indexed-email', title: 'Correo corporativo indexado', asset: 'ops@empresa.com', severity: 'high',
    rule: 'PUBLIC_EMAIL_EXPOSURE', sources: ['theHarvester'], confidence: 81, status: 'Revisado',
    description: 'Una cuenta operativa aparece indexada en una fuente pública del escenario.',
    impact: 9, traceFinding: 'Identidad pública', traceEvidence: 'Dirección indexada en fuente abierta',
  },
  {
    id: 'tls-expiry', title: 'Certificado TLS próximo a vencer', asset: 'api.empresa.com', severity: 'medium',
    rule: 'TLS_EXPIRY_WINDOW', sources: ['crt.sh'], confidence: 78, status: 'Abierto',
    description: 'La fecha de vencimiento del certificado entra en la ventana de atención configurada.',
    impact: 6, traceFinding: 'Vencimiento TLS', traceEvidence: 'Certificado · fecha de expiración',
  },
  {
    id: 'stale-subdomain', title: 'Subdominio sin actividad reciente', asset: 'old.empresa.com', severity: 'low',
    rule: 'STALE_SUBDOMAIN', sources: ['crt.sh', 'DNS'], confidence: 68, status: 'Aceptado',
    description: 'El subdominio se conserva en certificados históricos, pero no registra actividad reciente.',
    impact: 2, traceFinding: 'Subdominio histórico', traceEvidence: 'Certificado antiguo · DNS sin respuesta',
  },
  {
    id: 'admin-origin', title: 'Acceso administrativo sin restricción de origen', asset: 'admin.empresa.com', severity: 'critical',
    rule: 'ADMIN_ORIGIN_UNRESTRICTED', sources: ['Shodan', 'SpiderFoot'], confidence: 93, status: 'Abierto',
    description: 'La interfaz administrativa no muestra una restricción de origen en la evidencia de ejemplo.',
    impact: 16, traceFinding: 'Acceso amplio', traceEvidence: 'Respuesta HTTP · origen público',
  },
  {
    id: 'database-port', title: 'Puerto de base de datos accesible', asset: '189.203.•••.••:5432', severity: 'high',
    rule: 'PUBLIC_DATABASE_PORT', sources: ['Shodan'], confidence: 88, status: 'Abierto',
    description: 'La IP pública presenta un puerto de base de datos que requiere validar su alcance.',
    impact: 11, traceFinding: 'Servicio de datos', traceEvidence: 'Puerto 5432 · banner detectado',
  },
  {
    id: 'mail-policy', title: 'Política de correo incompleta', asset: 'empresa.com', severity: 'high',
    rule: 'MAIL_POLICY_GAP', sources: ['DNS', 'theHarvester'], confidence: 84, status: 'Revisado',
    description: 'Los registros de protección del correo no cubren todas las señales observadas.',
    impact: 8, traceFinding: 'Política de correo', traceEvidence: 'DNS · configuración parcial',
  },
  {
    id: 'api-debug', title: 'Información de depuración visible', asset: 'api.empresa.com', severity: 'high',
    rule: 'PUBLIC_DEBUG_INFO', sources: ['SpiderFoot', 'Shodan'], confidence: 82, status: 'Abierto',
    description: 'Una respuesta del API muestra detalles técnicos que conviene retirar de la vista pública.',
    impact: 8, traceFinding: 'Detalle técnico', traceEvidence: 'Respuesta API · mensaje de depuración',
  },
  {
    id: 'missing-headers', title: 'Cabeceras de seguridad incompletas', asset: 'www.empresa.com', severity: 'medium',
    rule: 'MISSING_SECURITY_HEADERS', sources: ['SpiderFoot'], confidence: 74, status: 'Abierto',
    description: 'La respuesta del sitio omite algunas cabeceras recomendadas por la regla de ejemplo.',
    impact: 5, traceFinding: 'Configuración web', traceEvidence: 'Respuesta HTTP · cabeceras ausentes',
  },
]

export const findingStats = {
  total: mockFindings.length,
  critical: mockFindings.filter((finding) => finding.severity === 'critical').length,
  highConfidence: mockFindings.filter((finding) => finding.confidence > 80).length,
  new: mockFindings.filter((finding) => finding.status === 'Nuevo').length,
} as const
