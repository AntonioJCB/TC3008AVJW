import { useState } from 'react'
import SourceCoverage from './components/SourceCoverage'
import SourceDetailDialog from './components/SourceDetailDialog'
import SourceInventory from './components/SourceInventory'
import SourceKpis from './components/SourceKpis'
import SourceNormalization from './components/SourceNormalization'
import SourceQuality from './components/SourceQuality'
import { useSourceExplorer } from './controller/useSourceExplorer'
import { sourceStats } from './services/sourcesMock'
import './sources.css'

export default function SourcesScreen() {
  const explorer = useSourceExplorer()
  const [detailOpen, setDetailOpen] = useState(false)
  const [testNotice, setTestNotice] = useState(false)

  return (
    <div className="sources-screen">
      <header className="sources-header">
        <h1 className="sr-only">Fuentes</h1>
        <div className="sources-header-actions">
          <span>Última consulta: hoy, 10:17</span>
          <button type="button" onClick={() => setTestNotice(true)}>Probar conexiones</button>
        </div>
      </header>
      {testNotice && <div className="sources-test-notice" role="status">Prueba simulada: {sourceStats.healthy} fuentes saludables y {sourceStats.partial} con respuesta parcial.</div>}
      <SourceKpis />
      <div className="sources-workspace">
        <SourceInventory {...explorer} />
        <aside className="sources-side" aria-label="Calidad y cobertura de fuentes">
          <SourceQuality source={explorer.selectedSource} onOpenDetail={() => setDetailOpen(true)} />
          <SourceCoverage />
          <SourceNormalization />
        </aside>
      </div>
      {detailOpen && explorer.selectedSource && <SourceDetailDialog source={explorer.selectedSource} onClose={() => setDetailOpen(false)} />}
    </div>
  )
}
