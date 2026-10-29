import { relationCanvas, relationEdges, relationNodes, type PriorityRoute } from '../services/relationsMock'
import { useRelationGraphNavigation } from '../controller/useRelationGraphNavigation'
import RelationGraphControls from './RelationGraphControls'

interface RelationGraphProps {
  selectedNodeId: string
  selectedRoute: PriorityRoute | null
  onSelectNode: (id: string) => void
  onReset: () => void
}

const nodeById = Object.fromEntries(relationNodes.map((node) => [node.id, node]))

export default function RelationGraph({ selectedNodeId, selectedRoute, onSelectNode, onReset }: RelationGraphProps) {
  const { viewportRef, canvas, view, dragging, zoomPercent, canZoomIn, canZoomOut, zoomIn, zoomOut, fitGraph, onPointerDown, onPointerMove, onPointerEnd, onKeyDown } = useRelationGraphNavigation(relationCanvas)

  return <section className="content-card relation-graph-card" aria-label="Grafo de exposición">
    <div className="relation-graph-toolbar">
      <div className="relation-legend" aria-label="Leyenda del grafo">
        <span><i className="tone-domain" />Dominio</span><span><i className="tone-service" />Servicio</span><span><i className="tone-identity" />Identidad</span><span><i className="tone-critical" />Ruta crítica</span>
      </div>
      <RelationGraphControls zoomPercent={zoomPercent} canZoomIn={canZoomIn} canZoomOut={canZoomOut} onZoomIn={zoomIn} onZoomOut={zoomOut} onFit={fitGraph} />
      {(selectedNodeId !== 'root' || selectedRoute) && <button type="button" className="relation-reset" onClick={onReset}>Restablecer foco</button>}
    </div>
    <div className={`relation-graph-viewport${dragging ? ' dragging' : ''}`} ref={viewportRef} role="group" aria-label="Pizarra de relaciones. Arrastra para mover; usa los controles para acercar o alejar." tabIndex={0} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerEnd} onPointerCancel={onPointerEnd} onKeyDown={onKeyDown}>
      <div className="relation-graph" style={{ width: canvas.width, height: canvas.height, transform: `translate3d(${view.x}px, ${view.y}px, 0) scale(${view.scale})` }} role="group" aria-label="Mapa de relaciones entre activos">
        <svg className="relation-edges" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          {relationEdges.map((edge) => {
            const from = nodeById[edge.from]
            const to = nodeById[edge.to]
            const highlighted = selectedRoute ? selectedRoute.edgeIds.includes(edge.id) : selectedNodeId !== 'root' && (edge.from === selectedNodeId || edge.to === selectedNodeId)
            return <line key={edge.id} className={`${edge.critical ? 'critical' : ''}${highlighted ? ' highlighted' : ''}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
          })}
        </svg>
        {relationNodes.map((node) => <button
          type="button"
          key={node.id}
          className={`relation-node tone-${node.tone}${node.id === 'root' ? ' root' : ''}${node.id === selectedNodeId ? ' selected' : ''}`}
          style={{ left: `${node.x}%`, top: `${node.y}%` }}
          aria-pressed={node.id === selectedNodeId}
          onClick={() => onSelectNode(node.id)}
        ><span>{node.badge}</span><strong>{node.name}</strong><small>{node.caption}</small></button>)}
      </div>
    </div>
  </section>
}
