import { useMemo, useState } from 'react'
import FindingDetailDialog from './components/FindingDetailDialog'
import FindingInsights from './components/FindingInsights'
import FindingQueue from './components/FindingQueue'
import FindingsKpis from './components/FindingsKpis'
import PriorityExplanationDialog from './components/PriorityExplanationDialog'
import { demoProject } from '../../services/demoData'
import { useFindingExplorer } from './controller/useFindingExplorer'
import { mockFindings } from './services/findingsMock'
import type { ClientData } from '../../services/clientData'
import { liveFindings, shortDate, shortTime } from '../../services/liveAdapters'
import './findings.css'

export default function FindingsScreen({ data }: { data?: ClientData }) {
  const records = useMemo(() => data ? liveFindings(data) : mockFindings, [data])
  const explorer = useFindingExplorer(records)
  const [detailOpen, setDetailOpen] = useState(false)
  const [explanationOpen, setExplanationOpen] = useState(false)
  const kpis = data ? [
    { label: 'TOTAL', value: data.findingCount, detail: 'Hallazgos registrados', tone: 'total' },
    { label: 'CRÍTICOS', value: records.filter((item) => item.severity === 'critical').length, detail: 'Requieren revisión', tone: 'critical' },
    { label: 'ALTA CONFIANZA', value: records.filter((item) => item.confidence > 80).length, detail: 'Confianza superior al 80%', tone: 'confidence' },
    { label: 'ABIERTOS', value: records.filter((item) => item.status === 'Abierto').length, detail: 'Pendientes de revisión', tone: 'new' },
  ] : undefined

  return (
    <div className="findings-screen">
      <header className="findings-header">
        <div>
          <h1>Hallazgos</h1>
          <p>Prioriza lo que requiere investigación y conserva el vínculo entre regla, evidencia, activo y fuente.</p>
        </div>
        <div className="findings-header-actions">
          <span>Actualizado {data ? `${shortDate(data.latestFinishedScan?.finalizado_en)}, ${shortTime(data.latestFinishedScan?.finalizado_en)}` : demoProject.lastAnalysis}</span>
          <button type="button" onClick={() => setExplanationOpen(true)}><span aria-hidden="true">✦</span> Explicar prioridades</button>
        </div>
      </header>
      <FindingsKpis values={kpis} />
      <div className="findings-workspace">
        <FindingQueue explorer={explorer} />
        <FindingInsights finding={explorer.selectedFinding} priority={explorer.selectedPriority} onOpenDetail={() => setDetailOpen(true)} />
      </div>
      {detailOpen && explorer.selectedFinding && <FindingDetailDialog finding={explorer.selectedFinding} onClose={() => setDetailOpen(false)} />}
      {explanationOpen && <PriorityExplanationDialog finding={explorer.selectedFinding} onClose={() => setExplanationOpen(false)} live={Boolean(data)} />}
    </div>
  )
}
