import { ScanSearch } from 'lucide-react'

export default function SourceTile({ name }: { name: string }) {
  return <div className="source-item"><span className="source-icon"><ScanSearch size={18} /></span><strong>{name}</strong><small>Pendiente de integración</small></div>
}
