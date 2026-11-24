const activeNames = new Set(['crt.sh', 'theHarvester', 'SpiderFoot', 'Web'])
const disabledPrefix = 'Fuente deshabilitada temporalmente:'

export function isActiveSource(name: string): boolean {
  return activeNames.has(name)
}

export function isDisabledSourceResult(result: { estado: string; error: string | null } | null | undefined): boolean {
  return result?.estado === 'deshabilitado'
    || (result?.estado === 'pendiente' && Boolean(result.error?.startsWith(disabledPrefix)))
}

export function sourceIssueSummary(error: string): string {
  const first = error.split(';')[0].trim()
  const marker = first.search(/\b(?:ReadTimeout|ConnectTimeout|TimeoutError|HTTPS|HTTP\s+\d{3}|rdap|theHarvester no completó|Proveedores omitidos)\b/i)
  const cause = marker >= 0 ? first.slice(marker) : first
  return cause.length > 120 ? `${cause.slice(0, 117)}…` : cause
}
