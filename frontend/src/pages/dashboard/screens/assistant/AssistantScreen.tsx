import { useState } from 'react'
import { ArrowRight, Sparkles } from 'lucide-react'
import { demoAnswers } from '../../services/demoData'
import AnswerPanel from './components/AnswerPanel'

export default function AssistantScreen() {
  const [topic, setTopic] = useState<keyof typeof demoAnswers>('risk')
  return (
    <section className="content-card assistant-section" aria-labelledby="assistant-title">
      <div className="section-heading"><div><div className="eyebrow">EXPLICACIÓN</div><h2 id="assistant-title">Asistente de análisis</h2><p>Respuestas preparadas para mostrar el recorrido visual.</p></div><Sparkles size={23} className="assistant-sparkle" /></div>
      <div className="assistant-notice">Este prototipo no llama a un modelo de IA. Selecciona una pregunta de ejemplo.</div>
      <div className="prompt-list">{(Object.keys(demoAnswers) as Array<keyof typeof demoAnswers>).map((key) => <button key={key} type="button" className={topic === key ? 'active' : ''} onClick={() => setTopic(key)}>{demoAnswers[key].question}<ArrowRight size={16} /></button>)}</div>
      <AnswerPanel answer={demoAnswers[topic].answer} />
    </section>
  )
}
