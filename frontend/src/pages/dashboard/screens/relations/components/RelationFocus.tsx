import type { RelationNode } from '../services/relationsMock'

export default function RelationFocus({ node }: { node: RelationNode }) {
  return <section className="content-card relation-focus-card" aria-labelledby="relation-focus-title">
    <span className="relation-panel-label">NODO SELECCIONADO</span>
    <span className="relation-kind-badge">{node.kind}</span>
    <h3 id="relation-focus-title">{node.name}</h3>
    <p>{node.description}</p>
    <div className="relation-impact"><span>Impacto o concentración</span><strong>{node.impact}</strong></div>
    <dl className="relation-facts">
      <div><dt>Fuentes</dt><dd>{node.sources.join(' · ')}</dd></div>
      <div><dt>Relacionado con</dt><dd>{node.related}</dd></div>
    </dl>
  </section>
}
