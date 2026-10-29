import { useState } from 'react'
import FindingDetailDialog from './components/FindingDetailDialog'
import FindingInsights from './components/FindingInsights'
import FindingQueue from './components/FindingQueue'
import FindingsKpis from './components/FindingsKpis'
import PriorityExplanationDialog from './components/PriorityExplanationDialog'
import { demoProject } from '../../services/demoData'
import { useFindingExplorer } from './controller/useFindingExplorer'
import './findings.css'

export default function FindingsScreen() {
  const explorer = useFindingExplorer()
  const [detailOpen, setDetailOpen] = useState(false)
  const [explanationOpen, setExplanationOpen] = useState(false)

  return (
    <div className="findings-screen">
      <header className="findings-header">
        <div>
          <h1>Hallazgos</h1>
          <p>Prioriza lo que requiere investigación y conserva el vínculo entre regla, evidencia, activo y fuente.</p>
        </div>
        <div className="findings-header-actions">
          <span>Actualizado {demoProject.lastAnalysis}</span>
          <button type="button" onClick={() => setExplanationOpen(true)}><span aria-hidden="true">✦</span> Explicar prioridades</button>
        </div>
      </header>
      <FindingsKpis />
      <div className="findings-workspace">
        <FindingQueue explorer={explorer} />
        <FindingInsights finding={explorer.selectedFinding} priority={explorer.selectedPriority} onOpenDetail={() => setDetailOpen(true)} />
      </div>
      {detailOpen && explorer.selectedFinding && <FindingDetailDialog finding={explorer.selectedFinding} onClose={() => setDetailOpen(false)} />}
      {explanationOpen && <PriorityExplanationDialog finding={explorer.selectedFinding} onClose={() => setExplanationOpen(false)} />}
    </div>
  )
}
