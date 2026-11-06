import type { AssetRecord, AssetKind, AssetExposure } from '../screens/assets/services/assetsMock'
import type { FindingRecord, FindingSeverity, FindingStatus } from '../screens/findings/services/findingsMock'
import type { HistoryEvent, HistoryScan } from '../screens/history/services/historyMock'
import type { PriorityRoute, RelationEdge, RelationNode } from '../screens/relations/services/relationsMock'
import type { ClientData } from './clientData'

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

function exposure(findings: ClientData['findings']): AssetExposure {
  if (!findings.length) return 'Sin evaluar'
  if (findings.some((finding) => severity(finding.severidad) === 'critical')) return 'Crítica'
  if (findings.some((finding) => severity(finding.severidad) === 'high')) return 'Alta'
  if (findings.some((finding) => severity(finding.severidad) === 'medium')) return 'Media'
  return 'Baja'
}

export function liveAssets(data: ClientData): AssetRecord[] {
  const sourceNames = new Map(data.sources.map((source) => [source.id, source.nombre]))
  return data.assets.map((asset) => {
    const relatedFindings = data.findings.filter((finding) => finding.activo_id === asset.id)
    const observations = data.observations.filter((observation) => observation.activo_id === asset.id)
    const sources = [...new Set([
      ...observations.map((observation) => sourceNames.get(observation.fuente_id)),
      ...relatedFindings.map((finding) => sourceNames.get(finding.fuente_id)),
    ].filter((name): name is string => Boolean(name)))]
    const kind = assetKind(asset.tipo)
    const isNew = Boolean(data.latestFinishedScan?.iniciado_en && new Date(asset.visto_primera_vez).getTime() >= new Date(data.latestFinishedScan.iniciado_en).getTime())
    return {
      id: asset.id,
      kind,
      value: asset.valor,
      detail: kind === 'Dominio' && asset.valor === data.organization.dominio_principal ? 'Dominio principal' : asset.tipo,
      exposure: exposure(relatedFindings),
      findings: relatedFindings.length,
      sources,
      observed: `${shortDate(asset.visto_ultima_vez)}, ${shortTime(asset.visto_ultima_vez)}`,
      observationState: isNew ? 'Nuevo' : 'Registrado',
      isNew,
      confidence: null,
      description: `Activo ${asset.tipo} registrado para ${data.organization.nombre}. Última observación: ${shortDate(asset.visto_ultima_vez)}.`,
    }
  })
}

function findingStatus(value: string): FindingStatus {
  const normalized = value.toLowerCase()
  if (normalized === 'nuevo') return 'Nuevo'
  if (normalized === 'revisado') return 'Revisado'
  if (normalized === 'aceptado') return 'Aceptado'
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
  const order = { critical: 0, high: 1, medium: 2, low: 3 }
  return data.findings.map((finding) => {
    const rule = finding.regla_id ? rules.get(finding.regla_id) : null
    const title = rule?.nombre ?? finding.categoria
    const asset = assets.get(finding.activo_id) ?? 'Activo registrado'
    return {
      id: finding.id,
      title,
      asset,
      severity: severity(finding.severidad),
      rule: rule?.codigo ?? finding.categoria,
      sources: [sources.get(finding.fuente_id) ?? 'Fuente registrada'],
      confidence: Math.round(finding.confianza * (finding.confianza <= 1 ? 100 : 1)),
      status: findingStatus(finding.estado),
      description: rule?.descripcion || `${finding.categoria} detectado en ${asset}.`,
      impact: null,
      traceFinding: finding.categoria,
      traceEvidence: evidenceSummary(finding.evidencia),
    }
  }).sort((a, b) => order[a.severity] - order[b.severity])
}

export function liveHistory(data: ClientData): HistoryEvent[] {
  const events: Array<HistoryEvent & { timestamp: number }> = []
  const sourceNames = new Map(data.sources.map((source) => [source.id, source.nombre]))
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

export function liveRelations(data: ClientData): { nodes: RelationNode[]; edges: RelationEdge[]; routes: PriorityRoute[] } {
  const positions = [[22, 24], [77, 21], [85, 63], [56, 83], [18, 73], [14, 49]]
  const assets = liveAssets(data).slice(0, positions.length)
  const findings = liveFindings(data)
  const nodes: RelationNode[] = [{ id: 'root', name: data.organization.dominio_principal, badge: 'DOM', kind: 'Organización', caption: `${data.assetCount} activos`, impact: `${data.assetCount} activos`, description: `Dominio principal de ${data.organization.nombre}. El mapa agrupa activos registrados para esta organización.`, sources: [], related: `${data.assetCount} activos registrados`, tone: 'domain', x: 50, y: 49 }]
  const edges: RelationEdge[] = []
  assets.forEach((asset, index) => {
    const related = findings.filter((finding) => finding.asset === asset.value)
    const tone = related.some((finding) => finding.severity === 'critical') ? 'critical' : asset.kind === 'Correo' ? 'identity' : asset.kind === 'IP pública' || asset.kind === 'Servicio' ? 'service' : 'domain'
    nodes.push({ id: asset.id, name: asset.value, badge: asset.kind === 'Correo' ? 'ID' : asset.kind === 'IP pública' ? 'IP' : asset.kind === 'Servicio' ? 'SV' : 'SUB', kind: asset.kind, caption: `${related.length} ${related.length === 1 ? 'hallazgo' : 'hallazgos'}`, impact: related.length ? `${related.length} ${related.length === 1 ? 'hallazgo' : 'hallazgos'}` : 'Sin hallazgos', description: asset.description, sources: asset.sources, related: data.organization.dominio_principal, tone, x: positions[index][0], y: positions[index][1] })
    edges.push({ id: `root-${asset.id}`, from: 'root', to: asset.id, critical: tone === 'critical' })
  })
  const routes: PriorityRoute[] = findings.filter((finding) => assets.some((asset) => asset.value === finding.asset)).slice(0, 3).map((finding) => {
    const asset = assets.find((item) => item.value === finding.asset)!
    return { id: finding.id, title: finding.title, path: `Organización → ${asset.kind.toLowerCase()}`, impact: finding.severity.toUpperCase(), nodeId: asset.id, edgeIds: [`root-${asset.id}`] }
  })
  return { nodes, edges, routes }
}
