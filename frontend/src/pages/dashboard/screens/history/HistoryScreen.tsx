import EmptyHistory from './components/EmptyHistory'

export default function HistoryScreen() {
  return (
    <section className="content-card simple-section" aria-labelledby="history-title">
      <div className="eyebrow">SEGUIMIENTO</div><h2 id="history-title">Historial de análisis</h2><p>Esta sección mostrará comparaciones entre análisis cuando existan ejecuciones guardadas.</p>
      <EmptyHistory />
    </section>
  )
}
