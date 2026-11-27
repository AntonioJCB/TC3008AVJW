import { useMemo } from 'react'
import { relationCanvas, relationEdges, relationNodes, type PriorityRoute, type RelationEdge, type RelationNode } from '../services/relationsMock'
import { routeRelationEdges } from '../services/relationLayout'
import { useRelationGraphNavigation } from '../controller/useRelationGraphNavigation'
import RelationGraphControls from './RelationGraphControls'

interface RelationGraphProps {
  selectedNodeId: string
  selectedRoute: PriorityRoute | null
  onSelectNode: (id: string) => void
  onReset: () => void
  nodes?: RelationNode[]
  edges?: RelationEdge[]
  canvasSize?: { width: number; height: number }
  omittedCount?: number
  showAll?: boolean
}

export default function RelationGraph({ selectedNodeId, selectedRoute, onSelectNode, onReset, nodes = relationNodes, edges = relationEdges, canvasSize, omittedCount = 0, showAll = false }: RelationGraphProps) {
  const contentSize = canvasSize ?? relationCanvas
  const { viewportRef, canvas, view, dragging, zoomPercent, canZoomIn, canZoomOut, zoomIn, zoomOut, fitGraph, onPointerDown, onPointerMove, onPointerEnd, onKeyDown } = useRelationGraphNavigation(contentSize, showAll)
  const paths = useMemo(() => routeRelationEdges(nodes, edges, canvas), [nodes, edges, canvas])
  const hasHistorical = showAll && nodes.some((node) => node.kind.includes('Histórico / sintético'))

  return <section className="content-card relation-graph-card" aria-label="Grafo de exposición">
    <div className="relation-graph-toolbar">
      <p className="relation-map-caption">{showAll ? 'Inventario completo' : 'Vista de enfoque'} · {nodes.length} nodos visibles{omittedCount > 0 ? ` · ${omittedCount} fuera de vista` : ''}</p>
      <div className="relation-legend" aria-label="Leyenda del grafo">
        <span><i className="tone-domain" />Dominio</span><span><i className="tone-service" />Servicio</span><span><i className="tone-identity" />Identidad</span><span><i className="tone-critical" />Ruta crítica</span>
      </div>
      <RelationGraphControls zoomPercent={zoomPercent} canZoomIn={canZoomIn} canZoomOut={canZoomOut} onZoomIn={zoomIn} onZoomOut={zoomOut} onFit={fitGraph} />
      {(selectedNodeId !== 'root' || selectedRoute) && <button type="button" className="relation-reset" onClick={onReset}>Restablecer foco</button>}
    </div>
    <div className={`relation-graph-viewport${dragging ? ' dragging' : ''}`} ref={viewportRef} role="group" aria-label="Pizarra de relaciones. Arrastra para mover; usa los controles para acercar o alejar." tabIndex={0} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerEnd} onPointerCancel={onPointerEnd} onKeyDown={onKeyDown}>
      <div className="relation-graph" style={{ width: canvas.width, height: canvas.height, transform: `translate3d(${view.x}px, ${view.y}px, 0) scale(${view.scale})` }} role="group" aria-label="Mapa de relaciones entre activos">
        {hasHistorical && <div className="relation-historical-zone" style={{ top: canvas.height - 290 }} aria-hidden="true"><span>Histórico / sintético</span></div>}
        <svg className="relation-edges" viewBox={`0 0 ${canvas.width} ${canvas.height}`} preserveAspectRatio="none" aria-hidden="true">
          {edges.map((edge) => {
            const path = paths.get(edge.id)
            if (!path) return null
            const highlighted = selectedRoute ? selectedRoute.edgeIds.includes(edge.id) : selectedNodeId !== 'root' && (edge.from === selectedNodeId || edge.to === selectedNodeId)
            return <path key={edge.id} className={`${edge.id.startsWith('dns-') ? 'dns' : 'observed'}${edge.historical ? ' historical' : ''}${edge.critical ? ' critical' : ''}${highlighted ? ' highlighted' : ''}`} d={path} />
          })}
        </svg>
        {nodes.map((node) => <button
          type="button"
          key={node.id}
          className={`relation-node tone-${node.tone}${node.id === 'root' ? ' root' : ''}${node.kind.includes('Histórico / sintético') ? ' historical' : ''}${node.id === selectedNodeId ? ' selected' : ''}`}
          style={{ left: `${node.x}%`, top: `${node.y}%` }}
          aria-pressed={node.id === selectedNodeId}
          title={`${node.name} · ${node.caption}${node.sources.length ? ` · ${node.sources.join(', ')}` : ''}`}
          onClick={() => onSelectNode(node.id)}
        ><span>{node.badge}</span><strong>{node.name}</strong><small>{node.caption}</small>{node.sources.length > 0 && <small className="relation-node-source">{node.sources.join(' · ')}</small>}</button>)}
      </div>
    </div>
  </section>
}
