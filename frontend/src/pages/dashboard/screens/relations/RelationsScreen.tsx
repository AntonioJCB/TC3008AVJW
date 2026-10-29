import PriorityRoutes from './components/PriorityRoutes'
import RelationFocus from './components/RelationFocus'
import RelationGraph from './components/RelationGraph'
import RelationMetrics from './components/RelationMetrics'
import { useRelationExplorer } from './controller/useRelationExplorer'
import './relations.css'

export default function RelationsScreen() {
  const explorer = useRelationExplorer()

  return <div className="relations-screen">
    <h2 className="sr-only">Relaciones</h2>
    <RelationMetrics />
    <div className="relations-workspace">
      <RelationGraph selectedNodeId={explorer.selectedNode.id} selectedRoute={explorer.selectedRoute} onSelectNode={explorer.selectNode} onReset={explorer.reset} />
      <aside className="relations-side" aria-label="Detalle de relaciones">
        <RelationFocus node={explorer.selectedNode} />
        <PriorityRoutes selectedRoute={explorer.selectedRoute} onSelectRoute={explorer.selectRoute} />
      </aside>
    </div>
  </div>
}
