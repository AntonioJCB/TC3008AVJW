import { useMemo } from 'react'
import { Link } from 'react-router'
import PriorityRoutes from './components/PriorityRoutes'
import RelationFocus from './components/RelationFocus'
import RelationGraph from './components/RelationGraph'
import RelationMetrics from './components/RelationMetrics'
import { useRelationExplorer } from './controller/useRelationExplorer'
import { priorityRoutes, relationEdges, relationNodes } from './services/relationsMock'
import type { ClientData } from '../../services/clientData'
import { liveRelations } from '../../services/liveAdapters'
import InfoTip from '../../components/InfoTip'
import './relations.css'

export default function RelationsScreen({ data }: { data?: ClientData }) {
  const graph = useMemo(() => data ? liveRelations(data) : { nodes: relationNodes, edges: relationEdges, routes: priorityRoutes, canvasSize: undefined }, [data])
  const explorer = useRelationExplorer(graph.nodes, graph.routes)
  const rootAsset = data?.assets.find(asset => asset.valor === data.organization.dominio_principal)
  const represented = new Set(graph.nodes.map(node => node.id))
  if (rootAsset) represented.add(rootAsset.id)
  const omitted = data?.assets.filter(asset => !represented.has(asset.id)) ?? []
  const unloaded = data ? Math.max(0, data.assetCount - data.assets.length) : 0
  const metrics = data ? [
    { label: 'CONEXIONES', value: graph.edges.length, tone: 'default' },
    { label: 'RUTAS PRIORITARIAS', value: graph.routes.length, tone: 'critical' },
    { label: 'AGRUPADOS / EXCLUIDOS', value: `0 / ${omitted.length + unloaded}`, tone: 'default' },
    { label: 'NODOS MOSTRADOS', value: graph.nodes.length, tone: 'concentration' },
  ] : undefined

  return <div className="relations-screen">
    <h2 className="sr-only">Relaciones</h2>
    <RelationMetrics values={metrics} />
    {data && <div className="relation-browser"><div className="portal-info-heading"><span>{data.assets.length} activos cargados</span><InfoTip label="relaciones del grafo" text="Las líneas continuas muestran DNS, las discontinuas nombres observados y las tenues evidencia histórica." /></div><p>Una IP compartida no implica propiedad.</p></div>}
    <div className="relations-workspace">
      <RelationGraph selectedNodeId={explorer.selectedNode.id} selectedRoute={explorer.selectedRoute} onSelectNode={explorer.selectNode} onReset={explorer.reset} nodes={graph.nodes} edges={graph.edges} canvasSize={graph.canvasSize} omittedCount={omitted.length + unloaded} showAll={Boolean(data)} />
      <aside className="relations-side" aria-label="Detalle de relaciones">
        <RelationFocus node={explorer.selectedNode} />
        <PriorityRoutes selectedRoute={explorer.selectedRoute} onSelectRoute={explorer.selectRoute} routes={graph.routes} />
      </aside>
    </div>
    {data && (omitted.length > 0 || unloaded > 0) && <div className="content-card relation-omitted" role="status">{omitted.length} activos cargados sin nodo; {unloaded} activos no llegaron en los datos cargados. <Link to="/home/activos">Consultar inventario</Link></div>}
  </div>
}
