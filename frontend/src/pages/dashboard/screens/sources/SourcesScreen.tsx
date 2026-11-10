import { useState } from 'react'
import SourceCoverage from './components/SourceCoverage'
import SourceDetailDialog from './components/SourceDetailDialog'
import SourceInventory from './components/SourceInventory'
import SourceKpis from './components/SourceKpis'
import SourceNormalization from './components/SourceNormalization'
import SourceQuality from './components/SourceQuality'
import { useSourceExplorer } from './controller/useSourceExplorer'
import './sources.css'

export default function SourcesScreen() {
  const explorer = useSourceExplorer()
  const [detailOpen, setDetailOpen] = useState(false)

  return (
    <div className="sources-screen">
      <h1 className="sr-only">Fuentes</h1>
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
