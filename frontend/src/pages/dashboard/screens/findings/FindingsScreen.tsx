import { useMemo, useState } from 'react'
import FindingDetailDialog from './components/FindingDetailDialog'
import FindingInsights from './components/FindingInsights'
import FindingQueue from './components/FindingQueue'
import FindingsKpis from './components/FindingsKpis'
import { useFindingExplorer } from './controller/useFindingExplorer'
import { mockFindings } from './services/findingsMock'
import type { ClientData } from '../../services/clientData'
import { liveFindings } from '../../services/liveAdapters'
import './findings.css'

export default function FindingsScreen({ data, onResolve }: { data?: ClientData; onResolve?: (findingId: string) => Promise<void> }) {
  const records = useMemo(() => data ? liveFindings(data) : mockFindings, [data])
  const explorer = useFindingExplorer(records)
  const [detailOpen, setDetailOpen] = useState(false)
  const [resolving, setResolving] = useState(false)
  const [resolveError, setResolveError] = useState<string | null>(null)
  const emptyMessage = data && records.length === 0
    ? data.scans.some((scan) => scan.estado === 'ejecutando')
      ? 'El nuevo análisis sigue en curso. Los hallazgos aparecerán cuando termine y se calcule el riesgo.'
      : 'El último análisis no produjo hallazgos de riesgo verificables. Los activos descubiertos siguen visibles en Activos y Relaciones.'
    : undefined
  async function resolveSelected() {
    if (!explorer.selectedFinding || !onResolve || resolving) return
    setResolving(true)
    setResolveError(null)
    try {
      await onResolve(explorer.selectedFinding.id)
      setDetailOpen(false)
    } catch (cause) {
      setResolveError(cause instanceof Error ? cause.message : 'No se pudo resolver el hallazgo.')
    } finally {
      setResolving(false)
    }
  }
  const kpis = data ? [
    { label: 'TOTAL', value: data.findingCount, detail: 'Hallazgos registrados', tone: 'total' },
    { label: 'CONFIRMADOS', value: records.filter((item) => item.evidenceLevel === 'confirmada').length, detail: 'Evidencia suficiente', tone: 'critical' },
    { label: 'POTENCIALES', value: records.filter((item) => item.evidenceLevel === 'potencial').length, detail: 'Requieren confirmación', tone: 'confidence' },
    { label: 'SIN CLASIFICAR', value: records.filter((item) => (item.evidenceLevel ?? 'sin_clasificar') === 'sin_clasificar').length, detail: 'Datos históricos', tone: 'new' },
  ] : undefined

  return (
    <div className="findings-screen">
      {!data && <h1 className="sr-only">Hallazgos</h1>}
      <FindingsKpis values={kpis} />
      <div className="findings-workspace">
        <FindingQueue explorer={explorer} emptyMessage={emptyMessage} />
        <FindingInsights finding={explorer.selectedFinding} priority={explorer.selectedPriority} onOpenDetail={() => setDetailOpen(true)} />
      </div>
      {detailOpen && explorer.selectedFinding && <FindingDetailDialog finding={explorer.selectedFinding} onClose={() => { setDetailOpen(false); setResolveError(null) }} onResolve={onResolve ? () => { void resolveSelected() } : undefined} resolving={resolving} error={resolveError} />}
    </div>
  )
}
