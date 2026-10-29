import { coverageByData, sourceStats } from '../services/sourcesMock'

export default function SourceCoverage() {
  return <section className="content-card source-coverage" aria-labelledby="source-coverage-heading">
    <div className="source-card-heading"><h2 id="source-coverage-heading">COBERTURA POR DATO</h2><strong>{sourceStats.coverage}%</strong></div>
    <div className="source-coverage-bars">{coverageByData.map((item) => <div className="source-coverage-row" key={item.label}>
      <span>{item.label}</span><div className="source-coverage-track" role="img" aria-label={`${item.label}: ${item.value}%`}><span style={{ width: `${item.value}%` }} /></div><strong>{item.value}%</strong>
    </div>)}</div>
  </section>
}
