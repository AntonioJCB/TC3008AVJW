import { useMemo, useState } from 'react'
import HistoryChart from './components/HistoryChart'
import HistoryComparison from './components/HistoryComparison'
import HistoryDetailDialog from './components/HistoryDetailDialog'
import HistoryKpis from './components/HistoryKpis'
import HistoryLog from './components/HistoryLog'
import { useHistoryExplorer } from './controller/useHistoryExplorer'
import { historyEvents, type HistoryEvent, type HistoryScan } from './services/historyMock'
import type { ClientData } from '../../services/clientData'
import { liveFindings, liveHistory, liveHistoryScans } from '../../services/liveAdapters'
import './history.css'

export default function HistoryScreen({ data }: { data?: ClientData }) {
  const events = useMemo(() => data ? liveHistory(data) : historyEvents, [data])
  const scans = useMemo(() => data ? liveHistoryScans(data) : [], [data])
  const comparableScans = useMemo(() => scans.filter((scan) => scan.status === 'completado'), [scans])
  const explorer = useHistoryExplorer(events)
  const [detailEvent, setDetailEvent] = useState<HistoryEvent | null>(null)
  const currentScore = comparableScans.at(-1)?.score
  const previousScore = comparableScans.at(-2)?.score
  const newAssets = data?.assets.filter((asset) => data.latestFinishedScan?.iniciado_en && new Date(asset.visto_primera_vez).getTime() >= new Date(data.latestFinishedScan.iniciado_en).getTime()).length ?? 0
  const kpis = data ? [
    { label: 'ÚLTIMO SCORE COMPLETO', value: currentScore ?? '—', detail: previousScore === undefined || currentScore === undefined ? 'Sin comparación previa' : `${currentScore - previousScore >= 0 ? '+' : ''}${currentScore - previousScore} desde el anterior`, tone: 'risk' },
    { label: 'ANÁLISIS COMPLETADOS', value: comparableScans.length, detail: 'Con puntaje comparable en el historial', tone: 'scans' },
    { label: 'ACTIVOS NUEVOS', value: newAssets, detail: 'Desde el último análisis', tone: 'assets' },
    { label: 'CAMBIOS RELEVANTES', value: events.length, detail: 'Eventos disponibles', tone: 'changes' },
  ] : undefined

  return (
    <div className="history-screen">
      {!data && <h1 className="sr-only">Historial</h1>}
      <HistoryKpis values={kpis} />
      <div className="history-top-grid">
        <HistoryChart scans={data ? scans : undefined} />
        {data ? <LiveHistoryComparison data={data} scans={comparableScans} newAssets={newAssets} /> : <HistoryComparison />}
      </div>
      <HistoryLog explorer={explorer} onOpenEvent={setDetailEvent} />
      {detailEvent && <HistoryDetailDialog event={detailEvent} onClose={() => setDetailEvent(null)} />}
    </div>
  )
}
function LiveHistoryComparison({ data, scans, newAssets }: { data: ClientData; scans: HistoryScan[]; newAssets: number }) {
  const current = scans.at(-1)
  const previous = scans.at(-2)
  const delta = current && previous ? current.score - previous.score : null
  const latestFindings = liveFindings(data).filter((finding) => data.findings.some((row) => row.id === finding.id && row.escaneo_id === data.latestFinishedScan?.id))
  return <aside className="content-card history-comparison" aria-labelledby="history-comparison-title"><span className="history-panel-label">COMPARACIÓN RÁPIDA</span><h2 id="history-comparison-title">{current?.date ?? 'Sin análisis'} vs. {previous?.date ?? 'sin anterior'}</h2><p>{delta === null ? 'La comparación aparecerá cuando existan dos análisis con puntaje.' : `El Risk Score ${delta > 0 ? 'subió' : delta < 0 ? 'bajó' : 'se mantuvo'} ${Math.abs(delta)} puntos entre los dos últimos análisis.`}</p><div className="history-score-comparison"><div><span>ANTERIOR</span><strong>{previous?.score ?? '—'}</strong><small>{previous?.date ?? '—'}</small></div><i>{delta === null ? '—' : `${delta > 0 ? '+' : ''}${delta}`}</i><div><span>ACTUAL</span><strong>{current?.score ?? '—'}</strong><small>{current?.date ?? '—'}</small></div></div><dl className="history-deltas"><div><dt>Activos nuevos</dt><dd>{newAssets}</dd></div><div><dt>Hallazgos del último análisis</dt><dd>{latestFindings.length}</dd></div><div><dt>Críticos</dt><dd>{latestFindings.filter((finding) => finding.severity === 'critical').length}</dd></div><div><dt>Fuentes fallidas</dt><dd>{data.sourceResults.filter((result) => result.estado === 'fallido').length}</dd></div></dl><div className="history-dominant-change"><span>HALLAZGO PRIORITARIO</span><strong>{latestFindings[0]?.title ?? 'Sin hallazgos'}</strong><small>{latestFindings[0]?.asset ?? 'En el último análisis registrado'}</small></div></aside>
}
