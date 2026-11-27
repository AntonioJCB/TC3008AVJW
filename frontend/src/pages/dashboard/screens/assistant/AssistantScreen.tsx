import { useState, type FormEvent } from 'react'
import { ArrowRight, Send, Sparkles } from 'lucide-react'
import { demoAnswers } from '../../services/demoData'
import { sendAssistantMessage, type AssistantMessage } from '../../services/assistantChat'
import AnswerPanel from './components/AnswerPanel'
import type { ClientData } from '../../services/clientData'
import './assistantScreen.css'

const suggestions = [
  'Resume el riesgo del último análisis.',
  '¿Qué hallazgos requieren atención primero?',
  '¿Qué limitaciones de cobertura tuvo el análisis?',
]

function AssistantChat({ scanId }: { scanId: string | null }) {
  const [messages, setMessages] = useState<AssistantMessage[]>([])
  const [draft, setDraft] = useState('')
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function ask(value: string) {
    const question = value.trim()
    if (!question || pendingQuestion) return
    setPendingQuestion(question)
    setError(null)
    setDraft('')
    const requestMessages: AssistantMessage[] = [...messages.slice(-10), { role: 'user', content: question }]
    try {
      const reply = await sendAssistantMessage(requestMessages, scanId)
      setMessages((current) => [...current, { role: 'user', content: question }, { role: 'assistant', content: reply.respuesta }])
    } catch (cause) {
      setDraft(question)
      setError(cause instanceof Error ? cause.message : 'No se pudo obtener respuesta del asistente.')
    } finally {
      setPendingQuestion(null)
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void ask(draft)
  }

  return <section className="content-card assistant-section assistant-chat" aria-labelledby="assistant-title">
    <div className="section-heading"><div><div className="eyebrow">ASISTENTE DE IA</div><h2 id="assistant-title">Chat con Claude</h2><p>Pregunta por los resultados de tu organización.</p></div><Sparkles size={23} className="assistant-sparkle" /></div>
    <p className="assistant-chat-context">{scanId ? 'Las respuestas usan el último análisis terminado y no modifican el Risk Score.' : 'Aún no hay un análisis terminado. Puedes preguntar cuándo habrá resultados para explicar.'}</p>
    {messages.length === 0 && <div className="assistant-chat-suggestions" aria-label="Preguntas sugeridas">{suggestions.map((question) => <button key={question} type="button" onClick={() => void ask(question)} disabled={pendingQuestion !== null}>{question}<ArrowRight size={16} /></button>)}</div>}
    <div className="assistant-chat-messages" role="log" aria-label="Conversación con el asistente" aria-live="polite">
      {messages.map((message, index) => <div key={index} className={'assistant-chat-message ' + message.role}><span>{message.role === 'user' ? 'TÚ' : 'BAXTERSEC · CLAUDE'}</span><p>{message.content}</p></div>)}
      {pendingQuestion && <><div className="assistant-chat-message user"><span>TÚ</span><p>{pendingQuestion}</p></div><div className="assistant-chat-message assistant"><span>BAXTERSEC · CLAUDE</span><p>Preparando respuesta…</p></div></>}
    </div>
    {error && <p className="client-error" role="alert">{error}</p>}
    <form className="assistant-chat-form" onSubmit={submit}>
      <label htmlFor="assistant-question">Tu pregunta</label>
      <textarea id="assistant-question" rows={3} maxLength={2000} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Pregúntame sobre el análisis, los hallazgos o el riesgo…" disabled={pendingQuestion !== null} />
      <button type="submit" disabled={!draft.trim() || pendingQuestion !== null}><Send size={17} />{pendingQuestion ? 'Consultando…' : 'Enviar'}</button>
    </form>
  </section>
}

export default function AssistantScreen({ data }: { data?: ClientData }) {
  const [topic, setTopic] = useState<keyof typeof demoAnswers>('risk')
  const [selected, setSelected] = useState(0)
  if (data) {
    const explanations = data.explanations
    return <>
      <AssistantChat key={data.latestFinishedScan?.id ?? 'sin-escaneo'} scanId={data.latestFinishedScan?.id ?? null} />
      <section className="content-card assistant-section assistant-saved" aria-labelledby="assistant-saved-title">
        <div className="section-heading"><div><div className="eyebrow">EXPLICACIONES</div><h2 id="assistant-saved-title">Explicaciones guardadas</h2><p>Respuestas registradas del último análisis.</p></div></div>
        {explanations.length ? <><div className="prompt-list">{explanations.map((item, index) => <button key={item.id} type="button" className={selected === index ? 'active' : ''} onClick={() => setSelected(index)}>Explicación {index + 1} · {new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium' }).format(new Date(item.creado_en))}<ArrowRight size={16} /></button>)}</div><AnswerPanel answer={explanations[selected]?.contenido ?? explanations[0].contenido} label="BAXTERSEC · EXPLICACIÓN GUARDADA" /></> : <p className="client-empty">No hay explicaciones guardadas para el último análisis.</p>}
      </section>
    </>
  }
  return <section className="content-card assistant-section" aria-labelledby="assistant-title">
    <div className="section-heading"><div><div className="eyebrow">EXPLICACIÓN</div><h2 id="assistant-title">Asistente de análisis</h2><p>Respuestas preparadas para mostrar el recorrido visual.</p></div><Sparkles size={23} className="assistant-sparkle" /></div>
    <div className="assistant-notice">Este prototipo no llama a un modelo de IA. Selecciona una pregunta de ejemplo.</div>
    <div className="prompt-list">{(Object.keys(demoAnswers) as Array<keyof typeof demoAnswers>).map((key) => <button key={key} type="button" className={topic === key ? 'active' : ''} onClick={() => setTopic(key)}>{demoAnswers[key].question}<ArrowRight size={16} /></button>)}</div>
    <AnswerPanel answer={demoAnswers[topic].answer} />
  </section>
}
