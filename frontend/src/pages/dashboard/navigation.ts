import { GitBranch, History, LayoutDashboard, Network, ScanSearch, Settings2, Sparkles, TriangleAlert } from 'lucide-react'

export const navigation = [
  { path: '/home', label: 'Resumen', section: 'resumen', group: 'PRINCIPAL', icon: LayoutDashboard },
  { path: '/home/activos', label: 'Activos', section: 'activos', group: 'DESCUBRIMIENTO', icon: Network },
  { path: '/home/relaciones', label: 'Relaciones', section: 'relaciones', group: 'DESCUBRIMIENTO', icon: GitBranch },
  { path: '/home/fuentes', label: 'Fuentes', section: 'fuentes', group: 'DESCUBRIMIENTO', icon: ScanSearch },
  { path: '/home/hallazgos', label: 'Hallazgos', section: 'hallazgos', group: 'SEGURIDAD', icon: TriangleAlert },
  { path: '/home/historial', label: 'Historial', section: 'historial', group: 'SEGURIDAD', icon: History },
  { path: '/home/asistente', label: 'Asistente', section: 'asistente', group: 'ANÁLISIS', icon: Sparkles },
  { path: '/home/configuracion', label: 'Configuración', section: 'configuracion', group: 'ANÁLISIS', icon: Settings2 },
] as const

export type DashboardSection = (typeof navigation)[number]['section']
export const navigationGroups = ['PRINCIPAL', 'DESCUBRIMIENTO', 'SEGURIDAD', 'ANÁLISIS'] as const
