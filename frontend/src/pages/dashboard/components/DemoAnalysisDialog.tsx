import { CircleHelp, X } from 'lucide-react'

export default function DemoAnalysisDialog({ onClose }: { onClose: () => void }) {
  return (
    <div className="demo-dialog-backdrop" onClick={onClose}>
      <section className="demo-dialog" role="dialog" aria-modal="true" aria-labelledby="demo-dialog-title" onClick={(event) => event.stopPropagation()}>
        <button className="dialog-close" type="button" aria-label="Cerrar" onClick={onClose}><X size={19} /></button>
        <CircleHelp size={27} className="dialog-icon" />
        <h2 id="demo-dialog-title">Nuevo análisis</h2>
        <p>Esta pantalla usa únicamente datos ficticios. El inicio de análisis estará disponible cuando se integre el backend.</p>
        <button className="dialog-confirm" type="button" onClick={onClose}>Entendido</button>
      </section>
    </div>
  )
}
