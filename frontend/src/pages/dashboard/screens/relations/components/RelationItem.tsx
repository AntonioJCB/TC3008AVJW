import { Network } from 'lucide-react'
import type { Asset } from '../../../services/demoData'

export default function RelationItem({ asset }: { asset: Asset }) {
  return <div className="relation-item"><span className="relation-line" /><Network size={17} /><div><strong>{asset.value}</strong><small>{asset.detail}</small></div></div>
}
