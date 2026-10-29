import { sourceStats } from '../services/sourcesMock'

const facts = [
  { label: 'Registros crudos', value: sourceStats.rawRecords },
  { label: 'Normalizados', value: sourceStats.normalized },
  { label: 'Duplicados', value: sourceStats.duplicates },
  { label: 'Activos finales', value: sourceStats.assets },
] as const

export default function SourceNormalization() {
  return <section className="content-card source-normalization" aria-labelledby="source-normalization-heading">
    <div className="source-card-heading"><h2 id="source-normalization-heading">NORMALIZACIÓN</h2><strong>{sourceStats.assets} activos</strong></div>
    <div className="source-normalization-facts">{facts.map((fact) => <div key={fact.label}><span>{fact.label}</span><strong>{fact.value}</strong></div>)}</div>
  </section>
}
