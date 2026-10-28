import type { AssetRecord } from '../services/assetsMock'

const kindMark: Record<AssetRecord['kind'], string> = {
  Dominio: 'D',
  Subdominio: 'S',
  'IP pública': 'IP',
  Correo: '@',
}

export default function AssetRow({ asset, selected, onSelect }: { asset: AssetRecord; selected: boolean; onSelect: () => void }) {
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
      <td><strong className={`asset-exposure exposure-${asset.exposure.toLowerCase()}`}>{asset.exposure}</strong><span className="asset-secondary">{asset.findings ? `${asset.findings} ${asset.findings === 1 ? 'hallazgo' : 'hallazgos'}` : 'Sin hallazgos'}</span></td>
      <td><strong className="asset-source-count">{asset.sources.length}</strong><span className="asset-secondary">{asset.sources.join(' · ')}</span></td>
      <td><strong className="asset-observed">{asset.observed}</strong><span className="asset-secondary">{asset.observationState}</span></td>
    </tr>
  )
}
