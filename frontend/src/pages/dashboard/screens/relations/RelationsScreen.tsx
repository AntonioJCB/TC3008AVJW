import { Globe2 } from 'lucide-react'
import { demoProject } from '../../services/demoData'
import RelationItem from './components/RelationItem'

export default function RelationsScreen() {
  return (
    <section className="content-card simple-section" aria-labelledby="relations-title">
      <div className="eyebrow">DESCUBRIMIENTO</div><h2 id="relations-title">Relaciones del dominio</h2><p>Vínculos del conjunto de prueba. El mapa completo se conectará a los datos normalizados.</p>
      <div className="relation-root"><Globe2 size={20} /><strong>{demoProject.domain}</strong></div>
      <div className="relation-list">{demoProject.assets.filter((asset) => asset.kind === 'Subdominio').map((asset) => <RelationItem asset={asset} key={asset.id} />)}</div>
    </section>
  )
}
