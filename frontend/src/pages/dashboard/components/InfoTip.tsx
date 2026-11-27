import { useId } from 'react'
import { Info } from 'lucide-react'

export default function InfoTip({ label, text }: { label: string; text: string }) {
  const id = useId()
  return <span className="portal-info"><button type="button" aria-label={`Información sobre ${label}`} aria-describedby={id}><Info size={16} aria-hidden="true" /></button><span id={id} className="portal-info-tooltip" role="tooltip">{text}</span></span>
}
