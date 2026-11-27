import type { AssetRecord, AssetKind, AssetExposure } from '../screens/assets/services/assetsMock'
import type { EvidenceLevel, FindingRecord, FindingSeverity, FindingStatus } from '../screens/findings/services/findingsMock'
import type { HistoryEvent, HistoryScan } from '../screens/history/services/historyMock'
import type { PriorityRoute, RelationEdge, RelationNode } from '../screens/relations/services/relationsMock'
import { layoutRelationNodes } from '../screens/relations/services/relationLayout'
import type { ClientData } from './clientData'
import { isActiveSource } from './sourcePolicy'

const dateFormatter = new Intl.DateTimeFormat('es-MX', { day: '2-digit', month: 'short' })
const timeFormatter = new Intl.DateTimeFormat('es-MX', { hour: '2-digit', minute: '2-digit' })

export function shortDate(value: string | null | undefined) {
  return value ? dateFormatter.format(new Date(value)) : '—'
}

export function shortTime(value: string | null | undefined) {
  return value ? timeFormatter.format(new Date(value)) : '—'
}

function assetKind(type: string): AssetKind {
  switch (type.toLowerCase()) {
    case 'dominio': return 'Dominio'
    case 'subdominio': return 'Subdominio'
    case 'ip': return 'IP pública'
    case 'correo': return 'Correo'
    default: return 'Servicio'
  }
}

function severity(value: string): FindingSeverity {
  const normalized = value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  if (normalized.startsWith('crit')) return 'critical'
  if (normalized.startsWith('alt') || normalized === 'high') return 'high'
  if (normalized.startsWith('med')) return 'medium'
  return 'low'
}

function exposure(calculated: string | undefined, findings: ClientData['findings']): AssetExposure {
  const valid = new Set<AssetExposure>(['Crítica', 'Alta', 'Media', 'Baja', 'Evaluado sin hallazgos', 'Evaluación parcial', 'Sin evaluar', 'Fuera de alcance', 'Sin evaluación compatible', 'Histórico/sintético'])
  if (findings.some((finding) => severity(finding.severidad) === 'critical')) return 'Crítica'
  if (findings.some((finding) => severity(finding.severidad) === 'high')) return 'Alta'
  if (findings.some((finding) => severity(finding.severidad) === 'medium')) return 'Media'
  if (findings.length) return 'Baja'
  if (calculated && valid.has(calculated as AssetExposure)) return calculated as AssetExposure
  return 'Sin evaluar'
}

function isDocumentationAsset(value: string): boolean {
  const address = value.match(/^(\d+\.\d+\.\d+\.\d+)(?::\d+\/\w+)?$/)?.[1]
  if (!address) return false
  const [a, b, c] = address.split('.').map(Number)
  return (a === 192 && b === 0 && c === 2)
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
}

export function liveAssets(data: ClientData): AssetRecord[] {
  const sourceNames = new Map(data.sources.filter(source => isActiveSource(source.nombre)).map((source) => [source.id, source.nombre]))
  const rules = new Map(data.rules.map((rule) => [rule.id, rule]))
  const latestObservationIds = new Set(data.observations.map((observation) => observation.id))
  const openStates = new Set(['abierto', 'nuevo', 'revisado', 'aceptado'])
  const latestRisk = data.risks.find((risk) => risk.escaneo_id === data.latestFinishedScan?.id)
  const coverageAssets = new Map(
    (latestRisk?.cobertura?.infraestructura?.activos ?? []).map((asset) => [asset.id, asset]),
  )
  return data.assets.map((asset) => {
    const currentObservations = data.observations.filter((observation) => observation.activo_id === asset.id)
    const allObservations = data.assetObservations.filter((observation) => observation.activo_id === asset.id)
    const sources = [...new Set(currentObservations
      .map((observation) => sourceNames.get(observation.fuente_id))
      .filter((name): name is string => typeof name === 'string' && isActiveSource(name)))].sort()
    const historicalSources = [...new Set(allObservations
      .filter((observation) => !latestObservationIds.has(observation.id) || !isActiveSource(sourceNames.get(observation.fuente_id) ?? ''))
      .map((observation) => sourceNames.get(observation.fuente_id))
      .filter((name): name is string => Boolean(name)))].sort()
    const associated = data.findings.filter((finding) => finding.activo_id === asset.id)
    const activeFindings = associated.filter((finding) => openStates.has(finding.estado)
      && Boolean(finding.regla_id && rules.get(finding.regla_id)?.esta_activa))
    const riskFindings = activeFindings.filter((finding) => finding.evidencia?.nivel_evidencia === 'confirmada'
      && (rules.get(finding.regla_id!)?.peso ?? 0) > 0)
    const informationalFindings = activeFindings.length - riskFindings.length
    const assetCoverage = coverageAssets.get(asset.id)
    const inferredExposure = assetCoverage?.clasificacion_exposicion === 'historico_sintetico' || isDocumentationAsset(asset.valor) ? 'Histórico/sintético'
      : assetCoverage?.motivo?.startsWith('Fuera del alcance') ? 'Fuera de alcance'
        : assetCoverage?.motivo?.startsWith('Tipo sin consulta compatible') ? 'Sin evaluación compatible'
          : undefined
    const persistedExposure = assetCoverage?.exposicion
    const evidenceExposure = assetCoverage?.estado_cobertura === 'evaluado' ? 'Evaluado sin hallazgos'
      : assetCoverage?.estado_cobertura === 'parcial' || assetCoverage?.consultas?.length ? 'Evaluación parcial' : undefined
    const effectiveExposure = persistedExposure && persistedExposure !== 'Sin evaluar'
      ? persistedExposure
      : inferredExposure ?? evidenceExposure ?? persistedExposure
    const calculatedExposure = exposure(effectiveExposure, riskFindings)
    const coverageState = assetCoverage?.estado_cobertura === 'evaluado' ? 'Evaluación aplicable completada'
      : assetCoverage?.estado_cobertura === 'parcial' ? 'Cobertura parcial'
        : calculatedExposure === 'Fuera de alcance' ? 'Fuera del alcance autorizado'
          : calculatedExposure === 'Sin evaluación compatible' ? 'Sin herramienta compatible'
            : calculatedExposure === 'Histórico/sintético' ? 'Evidencia histórica/sintética'
              : 'Sin evaluación de seguridad'
    const kind = assetKind(asset.tipo)
    const isNew = Boolean(data.latestFinishedScan?.iniciado_en && new Date(asset.visto_primera_vez).getTime() >= new Date(data.latestFinishedScan.iniciado_en).getTime())
    return {
      id: asset.id,
      kind,
      value: asset.valor,
      detail: kind === 'Dominio' && asset.valor === data.organization.dominio_principal ? 'Dominio principal' : asset.tipo,
      exposure: calculatedExposure,
      coverageState,
      findings: riskFindings.length,
      informationalFindings,
      sources,
      historicalSources,
      observed: `${shortDate(asset.visto_ultima_vez)}, ${shortTime(asset.visto_ultima_vez)}`,
      observationState: isNew ? 'Nuevo' : 'Registrado',
      isNew,
      confidence: riskFindings.length ? Math.round(Math.max(...riskFindings.map((finding) => finding.confianza)) * 100) : null,
      description: `Activo ${asset.tipo} registrado para ${data.organization.nombre}. Última observación: ${shortDate(asset.visto_ultima_vez)}. La exposición proviene del backend y la cobertura se informa por separado.`,
    }
  })
}

function findingStatus(value: string): FindingStatus {
  const normalized = value.toLowerCase()
  if (normalized === 'nuevo') return 'Nuevo'
  if (normalized === 'revisado') return 'Revisado'
  if (normalized === 'aceptado') return 'Aceptado'
  if (normalized === 'resuelto') return 'Resuelto'
  return 'Abierto'
}

function evidenceSummary(value: Record<string, unknown> | null): string {
  if (!value || !Object.keys(value).length) return 'Sin detalle de evidencia'
  const summary = Object.entries(value).slice(0, 2).map(([key, item]) => `${key}: ${typeof item === 'string' || typeof item === 'number' ? item : JSON.stringify(item)}`).join(' · ')
  return summary.length > 130 ? `${summary.slice(0, 127)}…` : summary
}

export function liveFindings(data: ClientData): FindingRecord[] {
  const assets = new Map(data.assets.map((asset) => [asset.id, asset.valor]))
  const sources = new Map(data.sources.map((source) => [source.id, source.nombre]))
  const rules = new Map(data.rules.map((rule) => [rule.id, rule]))
  const potential = data.risks.find((risk) => risk.escaneo_id === data.latestFinishedScan?.id)?.cobertura?.riesgo_potencial
  const potentialContributions = new Map((potential?.contribuciones ?? []).map((item) => [
    `${item.activo_id}:${item.regla}`, item,
  ]))
  const order = { critical: 0, high: 1, medium: 2, low: 3 }
  return data.findings.map((finding) => {
    const rule = finding.regla_id ? rules.get(finding.regla_id) : null
    const title = rule?.nombre ?? finding.categoria
    const asset = assets.get(finding.activo_id) ?? 'Activo registrado'
    const rawLevel = finding.evidencia?.nivel_evidencia
    const evidenceLevel: EvidenceLevel = rawLevel === 'confirmada' || rawLevel === 'potencial'
      ? rawLevel : 'sin_clasificar'
    const resolved = findingStatus(finding.estado) === 'Resuelto'
    const potentialContribution = potentialContributions.get(`${finding.activo_id}:${rule?.codigo ?? finding.categoria}`)
    const confirmedImpact = typeof finding.evidencia?.aporte === 'number' ? finding.evidencia.aporte : null
    const potentialImpact = typeof potentialContribution?.aporte_potencial === 'number'
      ? potentialContribution.aporte_potencial : null
    const contributesTo: NonNullable<FindingRecord['contributesTo']> = !resolved && evidenceLevel === 'confirmada' && rule?.esta_activa === true && confirmedImpact !== null
      ? 'confirmado' : !resolved && evidenceLevel === 'potencial' && potentialImpact !== null
        ? 'potencial' : 'ninguno'
    return {
      id: finding.id,
      title,
      asset,
      severity: severity(finding.severidad),
      rule: rule?.codigo ?? finding.categoria,
      sources: Array.isArray(finding.evidencia?.fuentes)
        ? finding.evidencia.fuentes.filter((name): name is string => typeof name === 'string')
        : [sources.get(finding.fuente_id) ?? 'Fuente registrada'],
      confidence: Math.round(finding.confianza * (finding.confianza <= 1 ? 100 : 1)),
      status: findingStatus(finding.estado),
      description: rule?.descripcion || `${finding.categoria} detectado en ${asset}.`,
      impact: confirmedImpact,
      traceFinding: finding.categoria,
      traceEvidence: evidenceSummary(finding.evidencia),
      pendingRevalidation: finding.evidencia?.pendiente_revalidacion === true,
      evidenceLevel,
      ruleActive: rule ? rule.esta_activa : null,
      potentialImpact,
      nonConfirmationReason: typeof finding.evidencia?.motivo_no_confirmado === 'string'
        ? finding.evidencia.motivo_no_confirmado : null,
      ageDays: typeof finding.evidencia?.antiguedad_dias === 'number' ? finding.evidencia.antiguedad_dias : null,
      contributesTo,
    }
  }).sort((a, b) => Number(a.status === 'Resuelto') - Number(b.status === 'Resuelto')
    || ({ confirmada: 0, potencial: 1, sin_clasificar: 2 }[a.evidenceLevel ?? 'sin_clasificar']
      - { confirmada: 0, potencial: 1, sin_clasificar: 2 }[b.evidenceLevel ?? 'sin_clasificar'])
    || order[a.severity] - order[b.severity])
}

export function liveHistory(data: ClientData): HistoryEvent[] {
  const events: Array<HistoryEvent & { timestamp: number }> = []
  const sourceNames = new Map(data.sources.filter(source => isActiveSource(source.nombre)).map((source) => [source.id, source.nombre]))
  const risks = new Map(data.risks.map((risk) => [risk.escaneo_id, risk]))
  for (const scan of data.scans) {
    const when = scan.finalizado_en ?? scan.iniciado_en
    if (!when) continue
    const score = risks.get(scan.id)?.puntaje_global
    events.push({ id: `scan-${scan.id}`, kind: 'scan', date: shortDate(when), time: shortTime(when), title: `Análisis ${scan.estado}`, detail: data.organization.dominio_principal, context: 'Fuentes OSINT', contextDetail: `Estado: ${scan.estado}`, impact: score === undefined ? '—' : String(score), impactDetail: 'Risk Score', impactTone: 'neutral', status: scan.estado, followUp: scan.estado === 'incompleto', timestamp: new Date(when).getTime() })
  }
  for (const asset of data.assets.slice(0, 25)) {
    const when = asset.visto_primera_vez
    events.push({ id: `asset-${asset.id}`, kind: 'asset', date: shortDate(when), time: shortTime(when), title: `${asset.tipo} registrado`, detail: asset.valor, context: data.organization.nombre, contextDetail: 'Activo del inventario', impact: '—', impactDetail: 'Sin impacto individual', impactTone: 'neutral', status: 'Registrado', followUp: false, timestamp: new Date(when).getTime() })
  }
  for (const result of data.sourceResults) {
    if (!sourceNames.has(result.fuente_id)) continue
    const when = result.finalizado_en ?? result.iniciado_en
    if (!when) continue
    events.push({ id: `source-${result.id}`, kind: 'source', date: shortDate(when), time: shortTime(when), title: `${sourceNames.get(result.fuente_id) ?? 'Fuente'}: ${result.estado}`, detail: result.error ?? `${result.observaciones_generadas} observaciones`, context: sourceNames.get(result.fuente_id) ?? 'Fuente OSINT', contextDetail: result.error ?? 'Resultado del último análisis', impact: '—', impactDetail: 'Resultado de fuente', impactTone: result.estado === 'fallido' ? 'warning' : 'neutral', status: result.estado, followUp: result.estado === 'fallido', timestamp: new Date(when).getTime() })
  }
  return events.sort((a, b) => b.timestamp - a.timestamp)
}

export function liveHistoryScans(data: ClientData): HistoryScan[] {
  const risks = new Map(data.risks.map((risk) => [risk.escaneo_id, risk]))
  return data.scans
    .filter((scan) => scan.finalizado_en && risks.has(scan.id))
    .map((scan) => ({
      date: shortDate(scan.finalizado_en),
      score: risks.get(scan.id)!.puntaje_global,
      occurredAt: scan.finalizado_en!,
      status: scan.estado === 'fallido' ? 'fallido' as const : scan.estado === 'completado' && !risks.get(scan.id)!.es_parcial ? 'completado' as const : 'incompleto' as const,
    }))
    .sort((a, b) => new Date(a.occurredAt).getTime() - new Date(b.occurredAt).getTime())
}

export function liveRelations(data: ClientData): { nodes: RelationNode[]; edges: RelationEdge[]; routes: PriorityRoute[]; canvasSize: { width: number; height: number } } {
  const domain = data.organization.dominio_principal
  const sourceNames = new Map(data.sources.map((source) => [source.id, source.nombre]))
  const domainSources = [...new Set(data.observations
    .filter((observation) => data.assets.some((asset) => asset.id === observation.activo_id && asset.valor === domain))
    .map((observation) => sourceNames.get(observation.fuente_id))
    .filter((name): name is string => Boolean(name)))]
  const findings = liveFindings(data).filter((finding) => finding.status !== 'Resuelto')
  const relatedToDomain = (asset: ClientData['assets'][number]) => asset.tipo === 'subdominio' && asset.valor.endsWith(`.${domain}`)
  const assets = liveAssets(data)
    .filter((asset) => asset.value !== domain)
    .sort((left, right) => {
      const leftAsset = data.assets.find((asset) => asset.id === left.id)
      const rightAsset = data.assets.find((asset) => asset.id === right.id)
      return Number(Boolean(rightAsset && relatedToDomain(rightAsset))) - Number(Boolean(leftAsset && relatedToDomain(leftAsset)))
    })
  const currentIds = new Set(data.observations.map(observation => observation.id))
  const evidence = [...data.observations, ...data.assetObservations.filter(observation => !currentIds.has(observation.id))]
  const nodes: RelationNode[] = [{ id: 'root', name: domain, badge: 'DOM', kind: 'Dominio principal', caption: `${data.assetCount} activos`, impact: `${data.assetCount} activos registrados`, description: `Dominio principal de ${data.organization.nombre}. Una resolución DNS no prueba propiedad de la IP compartida.`, sources: domainSources, related: `${data.assetCount} activos registrados`, tone: 'domain', x: 50, y: 50 }]
  const edges: RelationEdge[] = []
  assets.forEach((asset) => {
    const related = findings.filter((finding) => finding.asset === asset.value)
    const tone = related.some((finding) => finding.severity === 'critical') ? 'critical' : asset.kind === 'Correo' ? 'identity' : asset.kind === 'IP pública' || asset.kind === 'Servicio' ? 'service' : 'domain'
    const classification = asset.exposure === 'Histórico/sintético' ? 'Histórico / sintético' : asset.kind === 'IP pública' || asset.kind === 'Servicio' ? 'Infraestructura compartida o no atribuida' : asset.value.toLowerCase().endsWith(`.${domain.toLowerCase()}`) || asset.value.toLowerCase().endsWith(`@${domain.toLowerCase()}`) ? 'Nombre del dominio' : 'Externo / por verificar'
    nodes.push({ id: asset.id, name: asset.value, badge: asset.kind === 'Correo' ? 'ID' : asset.kind === 'IP pública' ? 'IP' : asset.kind === 'Servicio' ? 'SV' : 'SUB', kind: `${asset.kind} · ${classification}`, caption: classification, impact: related.length ? `${related.length} ${related.length === 1 ? 'hallazgo' : 'hallazgos'}` : 'Sin hallazgos', description: `${asset.description} ${classification}.`, sources: asset.sources, related: 'Sin vínculo verificado', tone, x: 50, y: 50 })
    const nameEvidence = evidence.find((observation) => observation.activo_id === asset.id && (observation.atributo === 'descubierto' || observation.atributo === 'correo' || observation.atributo === 'resuelve_a'))
    const belongsToDomain = asset.kind === 'Subdominio' && asset.value.toLowerCase().endsWith(`.${domain.toLowerCase()}`)
      || asset.kind === 'Correo' && asset.value.toLowerCase().endsWith(`@${domain.toLowerCase()}`)
    if (belongsToDomain && nameEvidence && asset.exposure !== 'Histórico/sintético') {
      edges.push({ id: `root-${asset.id}`, from: 'root', to: asset.id, critical: tone === 'critical', historical: !currentIds.has(nameEvidence.id) })
    }
  })
  const visibleNodeIds = new Set(nodes.map((node) => node.id))
  const rootAssetId = data.assets.find((asset) => asset.valor === domain)?.id
  const ips = new Map(data.assets.filter((asset) => asset.tipo === 'ip').map((asset) => [asset.valor, asset.id]))
  for (const observation of evidence) {
    if (observation.atributo !== 'resuelve_a' || typeof observation.datos?.ip !== 'string') continue
    const from = observation.activo_id === rootAssetId ? 'root' : observation.activo_id
    const to = ips.get(observation.datos.ip)
    if (to && visibleNodeIds.has(from) && visibleNodeIds.has(to)
      && !edges.some((edge) => edge.from === from && edge.to === to)) {
      edges.push({ id: `dns-${from}-${to}`, from, to, historical: !currentIds.has(observation.id) })
    }
  }
  const canvasSize = layoutRelationNodes(nodes, edges)
  const nodeNames = new Map(nodes.map((node) => [node.id, node.name]))
  nodes.forEach((node) => {
    const linked = edges.filter((edge) => edge.from === node.id || edge.to === node.id)
    node.related = linked.length ? linked.map((edge) => {
      const other = nodeNames.get(edge.from === node.id ? edge.to : edge.from) ?? 'Activo no disponible'
      return `${other} (${edge.id.startsWith('dns-') ? 'resolución DNS' : 'nombre observado'})`
    }).join(' · ') : 'Sin vínculo verificado en este mapa'
  })
  const routes: PriorityRoute[] = findings.filter((finding) => assets.some((asset) => asset.value === finding.asset && edges.some((edge) => edge.from === asset.id || edge.to === asset.id))).slice(0, 3).map((finding) => {
    const asset = assets.find((item) => item.value === finding.asset)!
    return { id: finding.id, title: finding.title, path: `Organización → ${asset.kind.toLowerCase()}`, impact: finding.severity.toUpperCase(), nodeId: asset.id, edgeIds: edges.filter((edge) => edge.to === asset.id || edge.from === asset.id).map((edge) => edge.id) }
  })
  return { nodes, edges, routes, canvasSize }
}
