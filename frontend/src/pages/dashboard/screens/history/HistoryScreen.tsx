import { useState } from 'react'
import HistoryChart from './components/HistoryChart'
import HistoryComparison from './components/HistoryComparison'
import HistoryComparisonDialog from './components/HistoryComparisonDialog'
import HistoryDetailDialog from './components/HistoryDetailDialog'
import HistoryKpis from './components/HistoryKpis'
import HistoryLog from './components/HistoryLog'
import { useHistoryExplorer } from './controller/useHistoryExplorer'
import type { HistoryEvent } from './services/historyMock'
import { demoProject } from '../../services/demoData'
import './history.css'

export default function HistoryScreen() {
  const explorer = useHistoryExplorer()
  const [comparisonOpen, setComparisonOpen] = useState(false)
  const [detailEvent, setDetailEvent] = useState<HistoryEvent | null>(null)

  return (
    <div className="history-screen">
      <header className="history-header">
        <div><h1>Historial</h1><p>Entiende qué cambió entre análisis, cuándo apareció cada señal y cómo impactó la exposición de la organización.</p></div>
        <div className="history-header-actions"><span>Último análisis: {demoProject.lastAnalysis}</span><button type="button" onClick={() => setComparisonOpen(true)}>Comparar análisis</button></div>
      </header>
      <HistoryKpis />
      <div className="history-top-grid">
        <HistoryChart range={explorer.range} onRangeChange={explorer.setRange} />
        <HistoryComparison />
      </div>
      <HistoryLog explorer={explorer} onOpenEvent={setDetailEvent} />
      {comparisonOpen && <HistoryComparisonDialog onClose={() => setComparisonOpen(false)} />}
      {detailEvent && <HistoryDetailDialog event={detailEvent} onClose={() => setDetailEvent(null)} />}
    </div>
  )
}
