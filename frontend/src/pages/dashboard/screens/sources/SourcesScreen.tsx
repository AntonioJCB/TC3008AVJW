import { plannedSources } from '../../services/demoData'
import SourceTile from './components/SourceTile'

export default function SourcesScreen() {
  return (
    <section className="content-card simple-section" aria-labelledby="sources-title">
      <div className="eyebrow">RECOLECCIÓN</div><h2 id="sources-title">Fuentes previstas</h2><p>La arquitectura contempla estos colectores pasivos. Ninguno está conectado en este prototipo.</p>
      <div className="source-grid">{plannedSources.map((source) => <SourceTile name={source} key={source} />)}</div>
    </section>
  )
}
