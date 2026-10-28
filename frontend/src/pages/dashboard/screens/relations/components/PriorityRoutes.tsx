import { priorityRoutes, type PriorityRoute } from '../services/relationsMock'

interface PriorityRoutesProps {
  selectedRoute: PriorityRoute | null
  onSelectRoute: (id: string) => void
}

export default function PriorityRoutes({ selectedRoute, onSelectRoute }: PriorityRoutesProps) {
  return <section className="content-card priority-routes-card" aria-labelledby="priority-routes-title">
    <div className="priority-routes-heading"><h3 id="priority-routes-title">RUTAS PRIORITARIAS</h3><strong>{priorityRoutes.length}</strong></div>
    <div className="priority-routes-list">
      {priorityRoutes.slice(0, 3).map((route, index) => <button type="button" key={route.id} className={selectedRoute?.id === route.id ? 'selected' : ''} aria-pressed={selectedRoute?.id === route.id} onClick={() => onSelectRoute(route.id)}>
        <span>{String(index + 1).padStart(2, '0')}</span><span><strong>{route.title}</strong><small>{route.path}</small></span>
      </button>)}
    </div>
    {selectedRoute && <div className="priority-route-detail" aria-live="polite"><span>Ruta seleccionada</span><strong>{selectedRoute.impact}</strong></div>}
  </section>
}
