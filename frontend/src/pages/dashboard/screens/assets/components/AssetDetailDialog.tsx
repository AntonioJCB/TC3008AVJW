import { useEffect, useRef } from 'react'
import { X } from 'lucide-react'
import type { AssetRecord } from '../services/assetsMock'

export default function AssetDetailDialog({ asset, onClose }: { asset: AssetRecord; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    closeRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKeyDown)
    return () => { window.removeEventListener('keydown', onKeyDown); previousFocus?.focus() }
  }, [onClose])

  return (
    <div className="asset-dialog-backdrop" role="presentation" onClick={(event) => { if (event.target === event.currentTarget) onClose() }}>
      <section className="asset-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="asset-dialog-title">
        <button className="asset-dialog-close" type="button" ref={closeRef} aria-label="Cerrar ficha" onClick={onClose}><X size={19} /></button>
        <span className="asset-panel-label">FICHA DEL ACTIVO · DATOS DE EJEMPLO</span>
        <span className="asset-kind-badge">{asset.kind.toUpperCase()}</span>
        <h2 id="asset-dialog-title">{asset.value}</h2>
        <p>{asset.description}</p>
        <dl className="asset-dialog-facts">
          <div><dt>Exposición</dt><dd className={`exposure-${asset.exposure.toLowerCase()}`}>{asset.exposure}</dd></div>
          <div><dt>Hallazgos</dt><dd>{asset.findings}</dd></div>
          <div><dt>Confianza</dt><dd>{asset.confidence}%</dd></div>
          <div><dt>Última observación</dt><dd>{asset.observed}</dd></div>
        </dl>
        <h3>Fuentes relacionadas</h3>
        <div className="asset-dialog-sources">{asset.sources.map((source) => <span key={source}>{source}</span>)}</div>
      </section>
    </div>
  )
}
