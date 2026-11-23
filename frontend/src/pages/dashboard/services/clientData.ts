import { supabase } from '../../../services/supabase'

export type Organization = { id: string; nombre: string; dominio_principal: string }
export type Scan = { id: string; solicitado_por: string; estado: string; iniciado_en: string | null; finalizado_en: string | null }
export type Asset = { id: string; tipo: string; valor: string; visto_primera_vez: string; visto_ultima_vez: string }
export type Authorization = { id: string; alcance: string; expira_en: string | null; revocada_en: string | null }
export type ScanCoverage = {
  version: number; cobertura_incompleta: boolean; objetivos_pendientes: string[]
  activos: {
    id: string; tipo: string; valor: string; incluido: boolean; consultado: boolean
    motivo: string | null; consultas: TargetQuery[]; evaluacion_seguridad: string
    evaluado_seguridad?: boolean; comprobaciones_seguridad?: Record<string, unknown>[]
    exposicion?: string; hallazgos_vigentes?: number
    estado_cobertura?: 'evaluado' | 'parcial' | 'sin_evaluacion' | 'fuera_alcance' | 'sin_compatibilidad' | 'historico_sintetico'
    clasificacion_exposicion?: 'sin_evaluacion' | 'fuera_alcance' | 'sin_compatibilidad' | 'historico_sintetico'
  }[]
  fuentes: Record<string, { estado: string; error: string | null; consultas: TargetQuery[] }>
}
export type TargetQuery = { objetivo: string; fuente?: string; estado: string; metodo: string; error: string | null }
export type ConfirmedRisk = {
  puntaje_global: number; infraestructura: number; identidad_digital: number; configuracion: number; fuga_de_datos: number
}
export type PotentialRiskSummary = ConfirmedRisk & {
  hallazgos: number; reglas: string[]
}
export type PotentialRisk = PotentialRiskSummary & {
  version: number; reglas_activas: PotentialRiskSummary; reglas_inactivas: PotentialRiskSummary
  contribuciones: { activo_id: string; regla: string; regla_activa: boolean; categoria: string; severidad: string; confianza: number; antiguedad_dias: number | null; factor_antiguedad: number; aporte_potencial: number }[]
  formula: string
}
export type EstimatedGlobalRisk = { puntaje_global: number; confirmado: number; potencial: number; ponderacion_confirmada: number; ponderacion_potencial: number; formula: string; contribuciones: { activo_id: string; regla: string; nivel_evidencia: string; aporte: number }[] }
export type Risk = { cobertura?: { infraestructura?: ScanCoverage; evaluadas?: string[]; no_evaluadas?: { codigo: string; motivo: string }[]; riesgo_confirmado?: ConfirmedRisk; riesgo_potencial?: PotentialRisk; riesgo_global_estimado?: EstimatedGlobalRisk }; escaneo_id: string; puntaje_global: number; infraestructura: number; identidad_digital: number; configuracion: number; fuga_de_datos: number; es_parcial: boolean; fuentes_faltantes: string[]; calculado_en: string }
export type Finding = { id: string; escaneo_id: string; categoria: string; severidad: string; confianza: number; estado: string; activo_id: string; fuente_id: string; regla_id: string | null; evidencia: Record<string, unknown> | null }
export type SourceResult = {
  id: string; fuente_id: string; resultado_crudo_id: string | null; estado: string; error: string | null
  iniciado_en: string | null; finalizado_en: string | null
  observaciones_generadas: number; observaciones_nuevas: number; observaciones_duplicadas: number
  activos_nuevos: number; activos_existentes: number; descartadas: Record<string, number>
}
export type RawSourceResult = { id: string; escaneo_id: string; estado: string; contenido: unknown; observado_en: string }
export type CrtshEvidence = {
  observations: { id: string; atributo: string; datos: Record<string, unknown>; observado_en: string; activos: { tipo: string; valor: string } | null }[]
  findings: { id: string; estado: string; severidad: string; evidencia: Record<string, unknown> | null; activos: { valor: string } | null; reglas_riesgo: { codigo: string; nombre: string } | null }[]
}
export type Observation = { id: string; activo_id: string; fuente_id: string; atributo: string; datos: Record<string, unknown>; observado_en: string }
export type Explanation = { id: string; contenido: string; creado_en: string }
export type Source = { id: string; nombre: string; tipo_acceso: string }
export type Rule = { id: string; codigo: string; nombre: string; descripcion: string | null; peso: number; esta_activa: boolean }

export type ClientData = {
  loadedAt: number
  organization: Organization
  scans: Scan[]
  scanCount: number
  assets: Asset[]
  assetCount: number
  authorizations: Authorization[]
  risks: Risk[]
  findings: Finding[]
  findingCount: number
  sourceResults: SourceResult[]
  observations: Observation[]
  assetObservations: Observation[]
  explanations: Explanation[]
  sources: Source[]
  rules: Rule[]
  latestFinishedScan: Scan | null
}

function assertResult(error: { message: string } | null) {
  if (error) throw new Error('No se pudieron consultar los datos de tu organización. Intenta actualizar la página.')
}

async function allRows<T>(query: (start: number, end: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>): Promise<T[]> {
  const rows: T[] = []
  const pageSize = 1000
  for (let start = 0; ; start += pageSize) {
    const result = await query(start, start + pageSize - 1)
    assertResult(result.error)
    const page = result.data ?? []
    rows.push(...page)
    if (page.length < pageSize) return rows
  }
}

export async function loadClientData(organizationId: string, scanId?: string): Promise<ClientData> {
  const client = supabase
  if (!client) throw new Error('Supabase no está configurado.')
  const [orgResult, scanResult, authorizationResult, sourceResult, ruleResult] = await Promise.all([
    client.from('organizaciones').select('id, nombre, dominio_principal').eq('id', organizationId).single(),
    client.from('escaneos').select('id, solicitado_por, estado, iniciado_en, finalizado_en', { count: 'exact' }).eq('organizacion_id', organizationId).order('finalizado_en', { ascending: false, nullsFirst: false }).limit(50),
    client.from('autorizaciones_dominio').select('id, alcance, expira_en, revocada_en').eq('organizacion_id', organizationId).order('autorizado_en', { ascending: false }).limit(100),
    client.from('fuentes_osint').select('id, nombre, tipo_acceso').order('nombre'),
    client.from('reglas_riesgo').select('id, codigo, nombre, descripcion, peso, esta_activa'),
  ])
  for (const result of [orgResult, scanResult, authorizationResult, sourceResult, ruleResult]) assertResult(result.error)
  if (!orgResult.data) throw new Error('No se encontró la organización de tu cuenta.')

  const scans = (scanResult.data ?? []) as Scan[]
  const latestFinishedScan = scans.find((scan) => Boolean(scan.finalizado_en) && scan.estado !== 'cancelado' && (!scanId || scan.id === scanId)) ?? null
  const scanIds = scans.map((scan) => scan.id)
  const [assets, findings, observations, riskResult, sourceStatusResult, explanationResult] = await Promise.all([
    allRows<Asset>((start, end) => client.from('activos').select('id, tipo, valor, visto_primera_vez, visto_ultima_vez').eq('organizacion_id', organizationId).order('visto_ultima_vez', { ascending: false }).order('id').range(start, end)),
    latestFinishedScan ? allRows<Finding>((start, end) => client.from('hallazgos').select('id, escaneo_id, categoria, severidad, confianza, estado, activo_id, fuente_id, regla_id, evidencia').eq('escaneo_id', latestFinishedScan.id).order('id').range(start, end)) : Promise.resolve([]),
    latestFinishedScan ? allRows<Observation>((start, end) => client.from('observaciones').select('id, activo_id, fuente_id, atributo, datos, observado_en').eq('escaneo_id', latestFinishedScan.id).order('id').range(start, end)) : Promise.resolve([]),
    scanIds.length ? client.from('puntajes_riesgo').select('escaneo_id, puntaje_global, infraestructura, identidad_digital, configuracion, fuga_de_datos, es_parcial, fuentes_faltantes, calculado_en, cobertura').in('escaneo_id', scanIds) : Promise.resolve({ data: [], error: null }),
    latestFinishedScan ? client.from('resultados_fuentes').select('id, fuente_id, resultado_crudo_id, estado, error, iniciado_en, finalizado_en, observaciones_generadas, observaciones_nuevas, observaciones_duplicadas, activos_nuevos, activos_existentes, descartadas').eq('escaneo_id', latestFinishedScan.id) : Promise.resolve({ data: [], error: null }),
    latestFinishedScan ? client.from('explicaciones_ia').select('id, contenido, creado_en').eq('escaneo_id', latestFinishedScan.id).order('creado_en', { ascending: false }).limit(20) : Promise.resolve({ data: [], error: null }),
  ])
  for (const result of [riskResult, sourceStatusResult, explanationResult]) assertResult(result.error)
  const assetIds = assets.map((asset) => asset.id)
  const assetObservationGroups = await Promise.all(Array.from({ length: Math.ceil(assetIds.length / 50) }, (_, index) => {
    const ids = assetIds.slice(index * 50, index * 50 + 50)
    return allRows<Observation>((start, end) => client.from('observaciones').select('id, activo_id, fuente_id, atributo, datos, observado_en').in('activo_id', ids).order('id').range(start, end))
  }))
  const currentFindings = findings.filter((finding) => finding.evidencia?.retirado_del_riesgo !== true)

  return {
    loadedAt: Date.now(),
    organization: orgResult.data as Organization,
    scans,
    scanCount: scanResult.count ?? scans.length,
    assets,
    assetCount: assets.length,
    authorizations: (authorizationResult.data ?? []) as Authorization[],
    risks: (riskResult.data ?? []) as Risk[],
    findings: currentFindings,
    findingCount: currentFindings.length,
    sourceResults: (sourceStatusResult.data ?? []) as SourceResult[],
    observations,
    assetObservations: assetObservationGroups.flat(),
    explanations: (explanationResult.data ?? []) as Explanation[],
    sources: (sourceResult.data ?? []) as Source[],
    rules: (ruleResult.data ?? []) as Rule[],
    latestFinishedScan,
  }
}

export async function loadSourceRawResult(rawId: string): Promise<RawSourceResult | null> {
  if (!supabase) throw new Error('Supabase no está configurado.')
  const { data, error } = await supabase.from('resultados_crudos')
    .select('id, escaneo_id, estado, contenido, observado_en')
    .eq('id', rawId)
    .maybeSingle()
  if (error) throw new Error('No se pudo cargar la respuesta original de esta fuente.')
  return data as RawSourceResult | null
}

export async function loadCrtshEvidence(scanId: string, sourceId: string): Promise<CrtshEvidence> {
  const client = supabase
  if (!client) throw new Error('Supabase no está configurado.')
  type ObservationRow = Omit<CrtshEvidence['observations'][number], 'activos'> & { activos: { tipo: string; valor: string }[] }
  type FindingRow = Omit<CrtshEvidence['findings'][number], 'activos' | 'reglas_riesgo'> & {
    activos: { valor: string }[]; reglas_riesgo: { codigo: string; nombre: string }[]
  }
  const [observationRows, findingRows] = await Promise.all([
    allRows<ObservationRow>((start, end) => client.from('observaciones')
      .select('id, atributo, datos, observado_en, activos(tipo, valor)')
      .eq('escaneo_id', scanId).eq('fuente_id', sourceId).order('id').range(start, end)),
    allRows<FindingRow>((start, end) => client.from('hallazgos')
      .select('id, estado, severidad, evidencia, activos(valor), reglas_riesgo(codigo, nombre)')
      .eq('escaneo_id', scanId).order('id').range(start, end)),
  ])
  return {
    observations: observationRows.map((row) => ({ ...row, activos: row.activos?.[0] ?? null })),
    findings: findingRows.filter((finding) => Array.isArray(finding.evidencia?.fuentes)
      && finding.evidencia.fuentes.includes('crt.sh')).map((row) => ({
      ...row, activos: row.activos?.[0] ?? null, reglas_riesgo: row.reglas_riesgo?.[0] ?? null,
    })),
  }
}
