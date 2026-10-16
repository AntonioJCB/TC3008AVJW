import { Activity, Database, Globe2, Mail } from 'lucide-react'
import type { Asset } from '../../../services/demoData'

export default function AssetRow({ asset }: { asset: Asset }) {
  const icon = asset.kind === 'Correo' ? <Mail size={17} /> : asset.kind === 'Puerto' ? <Activity size={17} /> : asset.kind === 'IP pública' ? <Database size={17} /> : <Globe2 size={17} />
  return <div className="asset-row"><span className="asset-icon">{icon}</span><div className="asset-name"><strong>{asset.value}</strong><small>{asset.detail}</small></div><span className="asset-kind">{asset.kind}</span></div>
}
