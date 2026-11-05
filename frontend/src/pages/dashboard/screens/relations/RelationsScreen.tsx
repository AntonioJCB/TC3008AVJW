import { useMemo } from 'react'
import PriorityRoutes from './components/PriorityRoutes'
import RelationFocus from './components/RelationFocus'
import RelationGraph from './components/RelationGraph'
import RelationMetrics from './components/RelationMetrics'
import { useRelationExplorer } from './controller/useRelationExplorer'
import { priorityRoutes, relationEdges, relationNodes } from './services/relationsMock'
import type { ClientData } from '../../services/clientData'
import { liveRelations } from '../../services/liveAdapters'
import './relations.css'

export default function RelationsScreen({ data }: { data?: ClientData }) {
  const graph = useMemo(() => data ? liveRelations(data) : { nodes: relationNodes, edges: relationEdges, routes: priorityRoutes }, [data])
  const explorer = useRelationExplorer(graph.nodes, graph.routes)
  const metrics = data ? [
    { label: 'CONEXIONES', value: graph.edges.length, tone: 'default' },
    { label: 'RUTAS PRIORITARIAS', value: graph.routes.length, tone: 'critical' },
    { label: 'ACTIVOS FUERA DEL MAPA', value: Math.max(0, data.assetCount - (graph.nodes.length - 1)), tone: 'default' },
    { label: 'ACTIVOS MOSTRADOS', value: graph.nodes.length - 1, tone: 'concentration' },
  ] : undefined

  return <div className="relations-screen">
    <h2 className="sr-only">Relaciones</h2>
    <RelationMetrics values={metrics} />
    <div className="relations-workspace">
      <RelationGraph selectedNodeId={explorer.selectedNode.id} selectedRoute={explorer.selectedRoute} onSelectNode={explorer.selectNode} onReset={explorer.reset} nodes={graph.nodes} edges={graph.edges} />
      <aside className="relations-side" aria-label="Detalle de relaciones">
        <RelationFocus node={explorer.selectedNode} />
        <PriorityRoutes selectedRoute={explorer.selectedRoute} onSelectRoute={explorer.selectRoute} routes={graph.routes} />
      </aside>
    </div>
  </div>
}
