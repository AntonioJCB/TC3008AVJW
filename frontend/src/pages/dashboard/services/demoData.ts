// Vista de demostración basada en backend/mock_data.json. No representa un escaneo real.
export type AssetKind = 'Subdominio' | 'IP pública' | 'Correo' | 'Puerto'
export type Severity = 'Crítico' | 'Medio'

export interface Asset {
  id: string
  kind: AssetKind
  value: string
  detail: string
}

export interface Finding {
  id: string
  severity: Severity
  title: string
  target: string
  description: string
}

export const demoProject = {
  company: 'Empresa Demo',
  domain: 'empresa.com',
  lastAnalysis: 'hoy, 10:32',
  score: 75,
  assets: [
    { id: 'sub-api', kind: 'Subdominio', value: 'api.empresa.com', detail: 'API pública' },
    { id: 'sub-dev', kind: 'Subdominio', value: 'dev.empresa.com', detail: 'Entorno de desarrollo' },
    { id: 'sub-mail', kind: 'Subdominio', value: 'mail.empresa.com', detail: 'Servicio de correo' },
    { id: 'ip-1', kind: 'IP pública', value: '192.0.2.10', detail: 'IP de documentación' },
    { id: 'ip-2', kind: 'IP pública', value: '192.0.2.11', detail: 'IP de documentación' },
    { id: 'email-1', kind: 'Correo', value: 'admin@empresa.com', detail: 'Correo corporativo' },
    { id: 'email-2', kind: 'Correo', value: 'soporte@empresa.com', detail: 'Correo corporativo' },
    { id: 'port-22', kind: 'Puerto', value: '22 / SSH', detail: 'Servicio en datos de ejemplo' },
    { id: 'port-80', kind: 'Puerto', value: '80 / HTTP', detail: 'Servicio en datos de ejemplo' },
    { id: 'port-443', kind: 'Puerto', value: '443 / HTTPS', detail: 'Servicio en datos de ejemplo' },
    { id: 'port-5432', kind: 'Puerto', value: '5432 / PostgreSQL', detail: 'Servicio en datos de ejemplo' },
  ] satisfies Asset[],
  findings: [
    {
      id: 'finding-1',
      severity: 'Crítico',
      title: 'Puerto SSH y base de datos expuestos en servidor DEV',
      target: 'dev.empresa.com',
      description: 'El escenario ficticio identifica servicios sensibles en el entorno de desarrollo. La exposición requiere validación y control de acceso.',
    },
    {
      id: 'finding-2',
      severity: 'Medio',
      title: 'Ausencia de registros SPF y DMARC',
      target: 'empresa.com',
      description: 'El escenario ficticio marca políticas de autenticación de correo pendientes de revisión.',
    },
  ] satisfies Finding[],
}

export const demoAnswers = {
  risk: {
    question: '¿Por qué el riesgo es alto?',
    answer: 'El puntaje 75/100 es el valor esperado del escenario ficticio. El hallazgo crítico de servicios sensibles en DEV es la señal principal. Todavía no existe un motor de cálculo conectado a esta vista.',
  },
  priority: {
    question: '¿Qué debería revisar primero?',
    answer: 'En el escenario de ejemplo, revisa el acceso a SSH y PostgreSQL del entorno DEV. Después confirma las políticas SPF y DMARC del dominio. Estas son recomendaciones ilustrativas.',
  },
  assets: {
    question: '¿Qué activos aparecen?',
    answer: 'La muestra contiene tres subdominios, dos direcciones IP de documentación, dos correos corporativos y cuatro puertos. Los datos provienen del archivo de prueba del backend.',
  },
} as const
