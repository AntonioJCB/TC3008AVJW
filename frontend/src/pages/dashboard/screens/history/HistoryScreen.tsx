import { useMemo, useState } from 'react'
import { X } from 'lucide-react'
import HistoryChart from './components/HistoryChart'
import HistoryComparison from './components/HistoryComparison'
import HistoryComparisonDialog from './components/HistoryComparisonDialog'
import HistoryDetailDialog from './components/HistoryDetailDialog'
import HistoryKpis from './components/HistoryKpis'
import HistoryLog from './components/HistoryLog'
import { useHistoryExplorer } from './controller/useHistoryExplorer'
import { historyEvents, type HistoryEvent, type HistoryRange, type HistoryScan } from './services/historyMock'
import { demoProject } from '../../services/demoData'
import type { ClientData } from '../../services/clientData'
import { liveFindings, liveHistory, liveHistoryScans, shortDate, shortTime } from '../../services/liveAdapters'
import './history.css'

export default function HistoryScreen({ data }: { data?: ClientData }) {
  const events = useMemo(() => data ? liveHistory(data) : historyEvents, [data])
  const scans = useMemo(() => data ? liveHistoryScans(data) : [], [data])
  const comparableScans = useMemo(() => scans.filter((scan) => scan.status === 'completado'), [scans])
  const scanRanges = useMemo<Record<HistoryRange, HistoryScan[]> | undefined>(() => {
    if (!data) return undefined
    const within = (days: number) => scans.filter((scan) => scan.occurredAt && new Date(scan.occurredAt).getTime() >= data.loadedAt - days * 86400000)
    return { '7D': within(7), '30D': within(30), '90D': within(90) }
  }, [data, scans])
  const explorer = useHistoryExplorer(events)
  const [comparisonOpen, setComparisonOpen] = useState(false)
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
      <header className="history-header">
        <div><h1>Historial</h1><p>Entiende qué cambió entre análisis, cuándo apareció cada señal y cómo impactó la exposición de la organización.</p></div>
        <div className="history-header-actions"><span>Último análisis: {data ? `${shortDate(data.latestFinishedScan?.finalizado_en)}, ${shortTime(data.latestFinishedScan?.finalizado_en)}` : demoProject.lastAnalysis}</span><button type="button" onClick={() => setComparisonOpen(true)} disabled={Boolean(data && comparableScans.length < 2)}>Comparar análisis</button></div>
      </header>
      <HistoryKpis values={kpis} />
      <div className="history-top-grid">
        <HistoryChart range={explorer.range} onRangeChange={explorer.setRange} scanRanges={scanRanges} live={Boolean(data)} />
        {data ? <LiveHistoryComparison data={data} scans={comparableScans} newAssets={newAssets} /> : <HistoryComparison />}
      </div>
      <HistoryLog explorer={explorer} onOpenEvent={setDetailEvent} />
      {comparisonOpen && (data ? <LiveComparisonDialog scans={comparableScans} onClose={() => setComparisonOpen(false)} /> : <HistoryComparisonDialog onClose={() => setComparisonOpen(false)} />)}
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

function LiveComparisonDialog({ scans, onClose }: { scans: HistoryScan[]; onClose: () => void }) {
  const current = scans.at(-1)
  const previous = scans.at(-2)
  return <div className="history-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="history-dialog" role="dialog" aria-modal="true" aria-labelledby="live-history-compare-title"><button className="history-dialog-close" type="button" aria-label="Cerrar comparación" onClick={onClose}><X size={18} /></button><span className="history-dialog-label">COMPARACIÓN DE ANÁLISIS</span><h2 id="live-history-compare-title">{current?.date} vs. {previous?.date}</h2><p>Diferencia entre los dos últimos análisis con puntaje registrado.</p><dl className="history-dialog-facts"><div><dt>Score anterior</dt><dd>{previous?.score ?? '—'}</dd></div><div><dt>Score actual</dt><dd>{current?.score ?? '—'}</dd></div><div><dt>Cambio</dt><dd>{current && previous ? `${current.score - previous.score > 0 ? '+' : ''}${current.score - previous.score}` : '—'}</dd></div></dl></section></div>
}
