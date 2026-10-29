import { Check, Minus, X } from 'lucide-react'
import type { SourceStatus } from '../services/sourcesMock'

const statusDetails = {
  healthy: { label: 'Saludable', Icon: Check },
  partial: { label: 'Parcial', Icon: Minus },
  error: { label: 'Error', Icon: X },
} as const

export default function SourceStatusIndicator({ status }: { status: SourceStatus }) {
  const { label, Icon } = statusDetails[status]

  return <span className={`source-status ${status}`} aria-label={`Estado: ${label}`}>
    <Icon size={14} strokeWidth={3} aria-hidden="true" />
    <span>{label}</span>
  </span>
}
