import { supabase } from '../../../services/supabase'

export type Organization = { id: string; nombre: string; dominio_principal: string }
export type Scan = { id: string; solicitado_por: string; estado: string; iniciado_en: string | null; finalizado_en: string | null }
export type Asset = { id: string; tipo: string; valor: string; visto_primera_vez: string; visto_ultima_vez: string }
export type Authorization = { id: string; alcance: string; expira_en: string | null; revocada_en: string | null }
export type Risk = { escaneo_id: string; puntaje_global: number; infraestructura: number; identidad_digital: number; configuracion: number; fuga_de_datos: number; es_parcial: boolean; fuentes_faltantes: string[]; calculado_en: string }
export type Finding = { id: string; escaneo_id: string; categoria: string; severidad: string; confianza: number; estado: string; activo_id: string; fuente_id: string; regla_id: string | null; evidencia: Record<string, unknown> | null }
export type SourceResult = {
  id: string; fuente_id: string; estado: string; error: string | null
  iniciado_en: string | null; finalizado_en: string | null
  observaciones_generadas: number; observaciones_nuevas: number; observaciones_duplicadas: number
  activos_nuevos: number; activos_existentes: number; descartadas: Record<string, number>
}
export type Observation = { id: string; activo_id: string; fuente_id: string; atributo: string; observado_en: string }
export type Explanation = { id: string; contenido: string; creado_en: string }
export type Source = { id: string; nombre: string; tipo_acceso: string }
export type Rule = { id: string; codigo: string; nombre: string; descripcion: string | null; peso: number }

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
  explanations: Explanation[]
  sources: Source[]
  rules: Rule[]
  latestFinishedScan: Scan | null
}

function assertResult(error: { message: string } | null) {
  if (error) throw new Error('No se pudieron consultar los datos de tu organización. Intenta actualizar la página.')
}

export async function loadClientData(organizationId: string): Promise<ClientData> {
  if (!supabase) throw new Error('Supabase no está configurado.')
  const [orgResult, scanResult, assetResult, authorizationResult, sourceResult, ruleResult] = await Promise.all([
    supabase.from('organizaciones').select('id, nombre, dominio_principal').eq('id', organizationId).single(),
    supabase.from('escaneos').select('id, solicitado_por, estado, iniciado_en, finalizado_en', { count: 'exact' }).eq('organizacion_id', organizationId).order('finalizado_en', { ascending: false, nullsFirst: false }).limit(50),
    supabase.from('activos').select('id, tipo, valor, visto_primera_vez, visto_ultima_vez', { count: 'exact' }).eq('organizacion_id', organizationId).order('visto_ultima_vez', { ascending: false }).limit(100),
    supabase.from('autorizaciones_dominio').select('id, alcance, expira_en, revocada_en').eq('organizacion_id', organizationId).order('autorizado_en', { ascending: false }).limit(100),
    supabase.from('fuentes_osint').select('id, nombre, tipo_acceso').order('nombre'),
    supabase.from('reglas_riesgo').select('id, codigo, nombre, descripcion, peso'),
  ])
  for (const result of [orgResult, scanResult, assetResult, authorizationResult, sourceResult, ruleResult]) assertResult(result.error)
  if (!orgResult.data) throw new Error('No se encontró la organización de tu cuenta.')

  const scans = (scanResult.data ?? []) as Scan[]
  const latestFinishedScan = scans.find((scan) => Boolean(scan.finalizado_en)) ?? null
  const scanIds = scans.map((scan) => scan.id)
  const [riskResult, findingResult, sourceStatusResult, observationResult, explanationResult] = await Promise.all([
    scanIds.length ? supabase.from('puntajes_riesgo').select('escaneo_id, puntaje_global, infraestructura, identidad_digital, configuracion, fuga_de_datos, es_parcial, fuentes_faltantes, calculado_en').in('escaneo_id', scanIds) : Promise.resolve({ data: [], error: null }),
    supabase.from('hallazgos').select('id, escaneo_id, categoria, severidad, confianza, estado, activo_id, fuente_id, regla_id, evidencia', { count: 'exact' }).limit(100),
    latestFinishedScan ? supabase.from('resultados_fuentes').select('id, fuente_id, estado, error, iniciado_en, finalizado_en, observaciones_generadas, observaciones_nuevas, observaciones_duplicadas, activos_nuevos, activos_existentes, descartadas').eq('escaneo_id', latestFinishedScan.id) : Promise.resolve({ data: [], error: null }),
    latestFinishedScan ? supabase.from('observaciones').select('id, activo_id, fuente_id, atributo, observado_en').eq('escaneo_id', latestFinishedScan.id).order('observado_en', { ascending: false }).limit(100) : Promise.resolve({ data: [], error: null }),
    latestFinishedScan ? supabase.from('explicaciones_ia').select('id, contenido, creado_en').eq('escaneo_id', latestFinishedScan.id).order('creado_en', { ascending: false }).limit(20) : Promise.resolve({ data: [], error: null }),
  ])
  for (const result of [riskResult, findingResult, sourceStatusResult, observationResult, explanationResult]) assertResult(result.error)

  return {
    loadedAt: Date.now(),
    organization: orgResult.data as Organization,
    scans,
    scanCount: scanResult.count ?? scans.length,
    assets: (assetResult.data ?? []) as Asset[],
    assetCount: assetResult.count ?? (assetResult.data ?? []).length,
    authorizations: (authorizationResult.data ?? []) as Authorization[],
    risks: (riskResult.data ?? []) as Risk[],
    findings: (findingResult.data ?? []) as Finding[],
    findingCount: findingResult.count ?? (findingResult.data ?? []).length,
    sourceResults: (sourceStatusResult.data ?? []) as SourceResult[],
    observations: (observationResult.data ?? []) as Observation[],
    explanations: (explanationResult.data ?? []) as Explanation[],
    sources: (sourceResult.data ?? []) as Source[],
    rules: (ruleResult.data ?? []) as Rule[],
    latestFinishedScan,
  }
}
