import { useState } from 'react'
import { ArrowRight, Sparkles } from 'lucide-react'
import { demoAnswers } from '../../services/demoData'
import AnswerPanel from './components/AnswerPanel'
import type { ClientData } from '../../services/clientData'

export default function AssistantScreen({ data }: { data?: ClientData }) {
  const [topic, setTopic] = useState<keyof typeof demoAnswers>('risk')
  const [selected, setSelected] = useState(0)
  if (data) {
    const explanations = data.explanations
    return <section className="content-card assistant-section" aria-labelledby="assistant-title"><div className="section-heading"><div><div className="eyebrow">EXPLICACIÓN</div><h2 id="assistant-title">Asistente de análisis</h2><p>Explicaciones guardadas del último análisis.</p></div><Sparkles size={23} className="assistant-sparkle" /></div><div className="assistant-notice">Aquí aparecen las explicaciones registradas para tu organización.</div>{explanations.length ? <><div className="prompt-list">{explanations.map((item, index) => <button key={item.id} type="button" className={selected === index ? 'active' : ''} onClick={() => setSelected(index)}>Explicación {index + 1} · {new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium' }).format(new Date(item.creado_en))}<ArrowRight size={16} /></button>)}</div><AnswerPanel answer={explanations[selected]?.contenido ?? explanations[0].contenido} label="BAXTERSEC · EXPLICACIÓN GUARDADA" /></> : <p className="client-empty">No hay explicaciones guardadas para el último análisis.</p>}</section>
  }
  return (
    <section className="content-card assistant-section" aria-labelledby="assistant-title">
      <div className="section-heading"><div><div className="eyebrow">EXPLICACIÓN</div><h2 id="assistant-title">Asistente de análisis</h2><p>Respuestas preparadas para mostrar el recorrido visual.</p></div><Sparkles size={23} className="assistant-sparkle" /></div>
      <div className="assistant-notice">Este prototipo no llama a un modelo de IA. Selecciona una pregunta de ejemplo.</div>
      <div className="prompt-list">{(Object.keys(demoAnswers) as Array<keyof typeof demoAnswers>).map((key) => <button key={key} type="button" className={topic === key ? 'active' : ''} onClick={() => setTopic(key)}>{demoAnswers[key].question}<ArrowRight size={16} /></button>)}</div>
      <AnswerPanel answer={demoAnswers[topic].answer} />
    </section>
  )
}
