import { Maximize2, Minus, Plus } from 'lucide-react'

interface RelationGraphControlsProps {
  zoomPercent: number
  canZoomIn: boolean
  canZoomOut: boolean
  onZoomIn: () => void
  onZoomOut: () => void
  onFit: () => void
}

export default function RelationGraphControls({ zoomPercent, canZoomIn, canZoomOut, onZoomIn, onZoomOut, onFit }: RelationGraphControlsProps) {
  return <div className="relation-graph-controls" role="group" aria-label="Zoom de la pizarra">
    <button type="button" aria-label="Alejar grafo" title="Alejar grafo" disabled={!canZoomOut} onClick={onZoomOut}><Minus size={15} aria-hidden="true" /></button>
    <output aria-live="polite">{zoomPercent}%</output>
    <button type="button" aria-label="Acercar grafo" title="Acercar grafo" disabled={!canZoomIn} onClick={onZoomIn}><Plus size={15} aria-hidden="true" /></button>
    <span className="relation-graph-controls-divider" aria-hidden="true" />
    <button type="button" aria-label="Mostrar grafo completo" title="Mostrar grafo completo" onClick={onFit}><Maximize2 size={15} aria-hidden="true" /></button>
  </div>
}
