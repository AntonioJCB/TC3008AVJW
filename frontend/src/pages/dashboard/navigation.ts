export const navigation = [
  { path: '/home', label: 'Resumen', section: 'resumen', group: 'Principal', icon: '▦' },
  { path: '/home/activos', label: 'Activos', section: 'activos', group: 'Descubrimiento', icon: '◇' },
  { path: '/home/relaciones', label: 'Relaciones', section: 'relaciones', group: 'Descubrimiento', icon: '⌘' },
  { path: '/home/fuentes', label: 'Fuentes', section: 'fuentes', group: 'Descubrimiento', icon: '⌕' },
  { path: '/home/hallazgos', label: 'Hallazgos', section: 'hallazgos', group: 'Seguridad', icon: '△' },
  { path: '/home/historial', label: 'Historial', section: 'historial', group: 'Seguridad', icon: '◔' },
  { path: '/home/asistente', label: 'Asistente', section: 'asistente', group: 'Análisis', icon: '✦' },
  { path: '/home/configuracion', label: 'Configuración', section: 'configuracion', group: 'Análisis', icon: '⚙' },
] as const

export type DashboardSection = (typeof navigation)[number]['section']
export const navigationGroups = ['Principal', 'Descubrimiento', 'Seguridad', 'Análisis'] as const