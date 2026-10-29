import { useState } from 'react'
import { priorityRoutes, relationNodes } from '../services/relationsMock'

export function useRelationExplorer() {
  const [selectedNodeId, setSelectedNodeId] = useState('root')
  const [selectedRouteId, setSelectedRouteId] = useState<string | null>(null)

  const selectedNode = relationNodes.find((node) => node.id === selectedNodeId) ?? relationNodes[0]
  const selectedRoute = priorityRoutes.find((route) => route.id === selectedRouteId) ?? null

  return {
    selectedNode,
    selectedRoute,
    selectNode: (id: string) => { setSelectedNodeId(id); setSelectedRouteId(null) },
    selectRoute: (id: string) => {
      const route = priorityRoutes.find((item) => item.id === id)
      if (route) { setSelectedNodeId(route.nodeId); setSelectedRouteId(route.id) }
    },
    reset: () => { setSelectedNodeId('root'); setSelectedRouteId(null) },
  }
}
