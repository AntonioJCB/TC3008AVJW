import type { AssetRecord } from '../services/assetsMock'

const kindMark: Record<AssetRecord['kind'], string> = {
  Dominio: 'D',
  Subdominio: 'S',
  'IP pública': 'IP',
  Correo: '@',
  Servicio: 'SV',
}

export default function AssetRow({ asset, selected, onSelect }: { asset: AssetRecord; selected: boolean; onSelect: () => void }) {
  const exposureDetail = asset.findings ? `${asset.findings} ${asset.findings === 1 ? 'hallazgo de riesgo' : 'hallazgos de riesgo'}`
    : asset.informationalFindings ? `${asset.informationalFindings} ${asset.informationalFindings === 1 ? 'señal informativa' : 'señales informativas'}`
      : asset.exposure === 'Evaluado sin hallazgos' ? 'Sin hallazgos'
        : asset.exposure === 'Fuera de alcance' ? 'No autorizado para evaluación'
          : asset.exposure === 'Sin evaluación compatible' ? 'Sin herramienta compatible'
            : asset.exposure === 'Histórico/sintético' ? 'Evidencia no confirmada'
              : 'Sin evaluación de seguridad'
  return (
    <tr
      className={`asset-table-row${selected ? ' selected' : ''}`}
      tabIndex={0}
      aria-selected={selected}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect() }
      }}
    >
      <td><div className="asset-type"><span className={`asset-type-mark kind-${asset.kind === 'IP pública' ? 'ip' : asset.kind.toLowerCase()}`}>{kindMark[asset.kind]}</span><span>{asset.kind}</span></div></td>
      <td><strong className="asset-primary">{asset.value}</strong><span className="asset-secondary">{asset.detail}</span></td>
      <td><strong className={`asset-exposure exposure-${asset.exposure.toLowerCase()}`}>{asset.exposure}</strong><span className="asset-secondary">{exposureDetail}</span>{asset.coverageState && <span className="asset-secondary">Cobertura: {asset.coverageState}</span>}</td>
      <td><strong className="asset-source-count">{asset.sources.length}</strong><span className="asset-secondary">{asset.sources.length ? `Último análisis: ${asset.sources.join(' · ')}` : 'Sin evidencia en el último análisis'}</span>{Boolean(asset.historicalSources?.length) && <span className="asset-secondary">Histórico: {asset.historicalSources!.join(' · ')}</span>}</td>
      <td><strong className="asset-observed">{asset.observed}</strong><span className="asset-secondary">{asset.observationState}</span></td>
    </tr>
  )
}
