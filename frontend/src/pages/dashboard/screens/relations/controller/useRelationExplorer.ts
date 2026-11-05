import { useState } from 'react'
import { priorityRoutes, relationNodes, type PriorityRoute, type RelationNode } from '../services/relationsMock'

export function useRelationExplorer(nodes: RelationNode[] = relationNodes, routes: PriorityRoute[] = priorityRoutes) {
  const [selectedNodeId, setSelectedNodeId] = useState('root')
  const [selectedRouteId, setSelectedRouteId] = useState<string | null>(null)

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? nodes[0]
  const selectedRoute = routes.find((route) => route.id === selectedRouteId) ?? null

  return {
    selectedNode,
    selectedRoute,
    selectNode: (id: string) => { setSelectedNodeId(id); setSelectedRouteId(null) },
    selectRoute: (id: string) => {
      const route = routes.find((item) => item.id === id)
      if (route) { setSelectedNodeId(route.nodeId); setSelectedRouteId(route.id) }
    },
    reset: () => { setSelectedNodeId('root'); setSelectedRouteId(null) },
  }
}
