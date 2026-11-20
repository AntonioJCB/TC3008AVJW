import type { Observation } from '../services/clientData'

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function unique(values: unknown[]): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && Boolean(value)))]
}

function uniqueObjects(values: unknown[]): Record<string, unknown>[] {
  const found = new Map<string, Record<string, unknown>>()
  values.forEach(value => {
    const selected = object(value)
    if (Object.keys(selected).length) found.set(JSON.stringify(selected), selected)
  })
  return [...found.values()]
}

function enrichmentSources(observation: Observation): string[] {
  const explicit = Array.isArray(observation.datos.fuentes_enriquecimiento)
    ? observation.datos.fuentes_enriquecimiento : [observation.datos.fuente_enriquecimiento]
  return unique(explicit)
}

export function isPotentialVulnerability(observation: Observation): boolean {
  return observation.atributo === 'cve'
    && observation.datos.verificado === false
    && enrichmentSources(observation).some(source => source === 'NVD' || source === 'OSV')
}

export const isNvdPotential = isPotentialVulnerability

export default function NvdPotentialEvidence({ observations }: { observations: Observation[] }) {
  const items = observations.filter(isPotentialVulnerability)
  if (!items.length) return null
  const sources = unique(items.flatMap(enrichmentSources)).sort()
  const cves = unique(items.map(item => item.datos.cve)).sort()
  const products = unique(items.flatMap(item => {
    const values = Array.isArray(item.datos.productos_versiones) ? item.datos.productos_versiones : []
    return values.map(value => {
      const product = object(value)
      return [product.producto, product.version].filter(Boolean).join(' ')
    })
  }))
  const cpes = unique(items.flatMap(item => {
    const values = Array.isArray(item.datos.productos_versiones) ? item.datos.productos_versiones : []
    return values.map(value => object(value).cpe)
  }))
  const packages = unique(items.flatMap(item => {
    const values = Array.isArray(item.datos.paquetes_versiones) ? item.datos.paquetes_versiones : []
    return values.map(value => {
      const selected = object(value)
      return [selected.ecosistema, selected.paquete, selected.version].filter(Boolean).join(' / ')
    })
  }))
  const nvd = items.map(item => object(item.datos.nvd))
  const osv = items.flatMap(item => Array.isArray(item.datos.osv) ? item.datos.osv.map(object) : [])
  const osvSeverities = osv.flatMap(value => Array.isArray(value.severidad) ? value.severidad.map(entry => object(entry).type) : [])
  const severities = unique([...nvd.map(value => object(value.cvss).severidad), ...osvSeverities]).sort()
  const published = unique([...nvd.map(value => value.publicado_en), ...osv.map(value => value.publicado_en)]).sort()
  const modified = unique([...nvd.map(value => value.modificado_en), ...osv.map(value => value.modificado_en)]).sort()
  const references = unique([
    ...items.flatMap(item => Array.isArray(item.datos.referencias_enriquecimiento)
      ? item.datos.referencias_enriquecimiento : []),
    ...nvd.map(value => value.referencia), ...osv.map(value => value.referencia),
  ])
  const referenceByIdentifier = new Map<string, string>()
  ;[...nvd, ...osv].forEach(value => {
    const identifier = typeof value.cve === 'string' ? value.cve : typeof value.id === 'string' ? value.id : ''
    if (identifier && typeof value.referencia === 'string') referenceByIdentifier.set(identifier, value.referencia)
  })
  const evidence = uniqueObjects(items.flatMap(item => Array.isArray(item.datos.evidencias_osint) ? item.datos.evidencias_osint : []))
  const providers = unique(evidence.map(value => object(value).proveedor))
  const exploitation = new Map(items.map(item => [String(item.datos.cve), object(item.datos.explotacion)]))
  const kevCount = [...exploitation.values()].filter(value => object(value.kev).presente === true).length
  const epssValues = [...exploitation.values()].map(value => object(value.epss).probabilidad)
    .filter((value): value is number => typeof value === 'number')
  const epssUpdated = unique([...exploitation.values()].map(value => object(value.epss).fecha_actualizacion)).sort()
  const attention = [...exploitation.values()].filter(value => ['prioritaria', 'elevada'].includes(String(value.prioridad_operativa))).length
  return <section className="report-nvd-potential" aria-label="Vulnerabilidades potenciales enriquecidas por NVD u OSV">
    <h4>{sources.join(' + ')}: {cves.length} vulnerabilidades potenciales, 0 verificadas</h4>
    <p>Coinciden con productos o paquetes y versiones observados históricamente. No confirman software vigente ni explotación y no aumentan el Risk Score.</p>
    {products.length > 0 && <p>Producto/versión: {products.join(', ')}. CPE: {cpes.join(', ') || 'No disponible'}.</p>}
    {packages.length > 0 && <p>Paquete/ecosistema/versión: {packages.join(', ')}.</p>}
    <p>CVSS informativo: {severities.join(', ') || 'Sin clasificación'}. Publicación NVD: {published.length ? `${published[0]} – ${published.at(-1)}` : 'sin fecha'}. Última modificación: {modified.at(-1) || 'sin fecha'}.</p>
    {exploitation.size > 0 && <p>Contexto de explotación: {kevCount} presentes en CISA KEV; EPSS máximo {epssValues.length ? `${(Math.max(...epssValues) * 100).toFixed(1)}%` : 'sin dato'}{epssUpdated.length ? `, actualizado ${epssUpdated.at(-1)}` : ''}. {attention} requieren mayor atención operativa. KEV y EPSS no cambian la verificación ni el Risk Score.</p>}
    <p>Evidencias OSINT originales conservadas: {evidence.length}{providers.length ? ` de ${providers.join(', ')}` : ''}.</p>
    <details><summary>Ver vulnerabilidades y referencias</summary><ul>{cves.map(cve => {
      const reference = referenceByIdentifier.get(cve) || references.find(value => value.endsWith(`/${cve}`))
      const context = exploitation.get(cve) || {}
      const kev = object(context.kev)
      const epss = object(context.epss)
      return <li key={cve}>{reference ? <a href={reference} target="_blank" rel="noreferrer">{cve}</a> : cve}
        {kev.presente === true ? ` · CISA KEV desde ${String(kev.fecha_incorporacion || 'fecha no indicada')}` : ''}
        {typeof epss.probabilidad === 'number' ? ` · EPSS ${(epss.probabilidad * 100).toFixed(1)}% · percentil ${typeof epss.percentil === 'number' ? (epss.percentil * 100).toFixed(1) : 'sin dato'}%` : ''}
      </li>
    })}</ul></details>
  </section>
}
