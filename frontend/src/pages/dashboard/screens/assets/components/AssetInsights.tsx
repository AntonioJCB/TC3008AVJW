import { assetStats, type AssetRecord } from '../services/assetsMock'

export default function AssetInsights({ asset, onOpenDetail }: { asset: AssetRecord | null; onOpenDetail: () => void }) {
  return (
    <aside className="asset-insights" aria-label="Detalle y calidad del análisis">
      <section className="content-card selected-asset-card" aria-labelledby="selected-asset-heading">
        <span className="asset-panel-label" id="selected-asset-heading">ACTIVO SELECCIONADO</span>
        {asset ? <>
          <span className="asset-kind-badge">{asset.kind.toUpperCase()}</span>
          <h3>{asset.value}</h3>
          <p>{asset.description}</p>
          <div className="asset-detail-metrics">
            <div><span>Exposición</span><strong className={`exposure-${asset.exposure.toLowerCase()}`}>{asset.exposure}</strong></div>
            <div><span>Hallazgos</span><strong>{asset.findings}</strong></div>
            <div><span>Fuentes</span><strong>{asset.sources.length}</strong></div>
            <div><span>Confianza</span><strong>{asset.confidence}%</strong></div>
          </div>
          <button className="asset-open-detail" type="button" onClick={onOpenDetail}>Abrir ficha del activo</button>
        </> : <p className="asset-selection-empty">Selecciona un activo del inventario para ver sus detalles.</p>}
      </section>
      <section className="content-card asset-quality-card" aria-labelledby="asset-quality-heading">
        <div className="asset-quality-heading"><h3 id="asset-quality-heading">CALIDAD DEL ANÁLISIS</h3><strong>{assetStats.coverage}%</strong></div>
        <div className="asset-quality-grid">
          <div><span>Registros crudos</span><strong>{assetStats.rawRecords}</strong></div>
          <div><span>Normalizados</span><strong>{assetStats.normalizedRecords}</strong></div>
          <div><span>Duplicados fusionados</span><strong>{assetStats.mergedDuplicates}</strong></div>
          <div><span>Activos finales</span><strong>{assetStats.total}</strong></div>
        </div>
        <div className="asset-coverage"><span>Cobertura</span><strong>3 / 4 fuentes</strong></div>
        <div className="asset-coverage-track" role="img" aria-label={`Cobertura ilustrativa: ${assetStats.coverage}%`}><span style={{ width: `${assetStats.coverage}%` }} /></div>
      </section>
    </aside>
  )
}
