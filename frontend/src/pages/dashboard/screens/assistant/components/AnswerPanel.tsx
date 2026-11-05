import { Sparkles } from 'lucide-react'

export default function AnswerPanel({ answer, label = 'BAXTERSEC · RESPUESTA ILUSTRATIVA' }: { answer: string; label?: string }) {
  return <div className="assistant-answer"><span className="answer-avatar"><Sparkles size={17} /></span><div><div className="answer-label">{label}</div><p>{answer}</p></div></div>
}
