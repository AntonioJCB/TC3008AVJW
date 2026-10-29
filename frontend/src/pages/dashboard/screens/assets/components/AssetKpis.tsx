import { assetStats } from '../services/assetsMock'

const kpis = [
  { label: 'TOTAL', value: assetStats.total, detail: `${assetStats.mergedDuplicates} duplicados fusionados`, tone: 'total' },
  { label: 'SUBDOMINIOS', value: assetStats.subdomains, detail: `${assetStats.associatedFindings} con hallazgos asociados`, tone: 'subdomains' },
  { label: 'IPS PÚBLICAS', value: assetStats.publicIps, detail: `${assetStats.observedServices} servicios observados`, tone: 'ips' },
  { label: 'NUEVOS', value: `+${assetStats.newAssets}`, detail: 'Desde el análisis anterior', tone: 'new' },
] as const

export default function AssetKpis() {
  return (
    <div className="asset-kpis" aria-label="Indicadores de activos">
      {kpis.map((kpi) => (
        <div className={`content-card asset-kpi tone-${kpi.tone}`} key={kpi.label}>
          <span>{kpi.label}</span><strong>{kpi.value}</strong><small>{kpi.detail}</small>
        </div>
      ))}
    </div>
  )
}
