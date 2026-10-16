import { Sparkles } from 'lucide-react'

export default function AnswerPanel({ answer }: { answer: string }) {
  return <div className="assistant-answer"><span className="answer-avatar"><Sparkles size={17} /></span><div><div className="answer-label">BAXTERSEC · RESPUESTA ILUSTRATIVA</div><p>{answer}</p></div></div>
}
