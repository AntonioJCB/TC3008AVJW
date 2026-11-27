import { useEffect, useId, useRef, useState } from 'react'
import { CalendarDays, ChevronLeft, ChevronRight } from 'lucide-react'
import './dateFilterPicker.css'

interface DateFilterPickerProps {
  label: string
  value: string
  min?: string
  max?: string
  onChange: (value: string) => void
}

const weekdays = ['L', 'M', 'M', 'J', 'V', 'S', 'D']

function dateKey(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

function selectedMonth(value: string) {
  const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  return parts ? new Date(Number(parts[1]), Number(parts[2]) - 1, 1) : new Date(new Date().getFullYear(), new Date().getMonth(), 1)
}

export default function DateFilterPicker({ label, value, min, max, onChange }: DateFilterPickerProps) {
  const [open, setOpen] = useState(false)
  const [month, setMonth] = useState(() => selectedMonth(value))
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const panelId = useId()
  const year = month.getFullYear()
  const monthIndex = month.getMonth()
  const offset = (new Date(year, monthIndex, 1).getDay() + 6) % 7
  const dayCount = new Date(year, monthIndex + 1, 0).getDate()
  const cells = Array.from({ length: offset + dayCount }, (_, index) => index < offset ? null : index - offset + 1)
  const today = dateKey(new Date())
  const todayDisabled = Boolean((min && today < min) || (max && today > max))

  useEffect(() => {
    if (!open) return
    const closeOutside = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const closeEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setOpen(false); triggerRef.current?.focus() }
    }
    document.addEventListener('pointerdown', closeOutside)
    document.addEventListener('keydown', closeEscape)
    return () => {
      document.removeEventListener('pointerdown', closeOutside)
      document.removeEventListener('keydown', closeEscape)
    }
  }, [open])

  const display = value ? new Intl.DateTimeFormat('es-MX', { day: '2-digit', month: 'short', year: 'numeric' }).format(
    new Date(Number(value.slice(0, 4)), Number(value.slice(5, 7)) - 1, Number(value.slice(8, 10))),
  ) : 'Elegir fecha'

  return <div className="date-filter-picker" ref={rootRef}>
    <span className="date-filter-label">{label}</span>
    <button type="button" className="date-filter-trigger" ref={triggerRef} aria-label={`${label}: ${display}`} aria-expanded={open} aria-controls={open ? panelId : undefined} onClick={() => { setMonth(selectedMonth(value)); setOpen(!open) }}>
      <CalendarDays size={15} aria-hidden="true" /><span>{display}</span>
    </button>
    {open && <div className="date-filter-popover" id={panelId} role="group" aria-label={`Calendario ${label.toLowerCase()}`}>
      <div className="date-filter-month">
        <button type="button" aria-label="Mes anterior" onClick={() => setMonth(new Date(year, monthIndex - 1, 1))}><ChevronLeft size={16} /></button>
        <strong>{new Intl.DateTimeFormat('es-MX', { month: 'long', year: 'numeric' }).format(month)}</strong>
        <button type="button" aria-label="Mes siguiente" onClick={() => setMonth(new Date(year, monthIndex + 1, 1))}><ChevronRight size={16} /></button>
      </div>
      <div className="date-filter-grid">
        {weekdays.map((day, index) => <span className="date-filter-weekday" key={`${day}-${index}`}>{day}</span>)}
        {cells.map((day, index) => {
          if (day === null) return <span key={`empty-${index}`} />
          const date = new Date(year, monthIndex, day)
          const key = dateKey(date)
          const disabled = Boolean((min && key < min) || (max && key > max))
          return <button type="button" key={key} disabled={disabled} aria-label={new Intl.DateTimeFormat('es-MX', { dateStyle: 'full' }).format(date)} aria-pressed={value === key} className={value === key ? 'selected' : key === today ? 'today' : ''} onClick={() => { onChange(key); setOpen(false); triggerRef.current?.focus() }}>{day}</button>
        })}
      </div>
      <div className="date-filter-actions">
        <button type="button" disabled={todayDisabled} onClick={() => { onChange(today); setOpen(false); triggerRef.current?.focus() }}>Hoy</button>
        {value && <button type="button" onClick={() => { onChange(''); setOpen(false); triggerRef.current?.focus() }}>Borrar</button>}
      </div>
    </div>}
  </div>
}
