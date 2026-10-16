import { Globe2 } from 'lucide-react'
import type { Finding } from '../../../services/demoData'

export default function FindingCard({ finding }: { finding: Finding }) {
  return <article className="finding-card"><div className="finding-card-top"><span className={`severity-badge ${finding.severity === 'Crítico' ? 'critical' : 'medium'}`}>{finding.severity}</span><span>Datos de ejemplo</span></div><h3>{finding.title}</h3><div className="finding-target"><Globe2 size={14} />{finding.target}</div><p>{finding.description}</p></article>
}
