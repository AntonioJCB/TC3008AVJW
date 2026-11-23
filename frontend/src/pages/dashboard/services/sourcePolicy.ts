const activeNames = new Set(['crt.sh', 'theHarvester', 'SpiderFoot'])
const disabledPrefix = 'Fuente deshabilitada temporalmente:'

export function isActiveSource(name: string): boolean {
  return activeNames.has(name)
}

export function isDisabledSourceResult(result: { estado: string; error: string | null } | null | undefined): boolean {
  return result?.estado === 'deshabilitado'
    || (result?.estado === 'pendiente' && Boolean(result.error?.startsWith(disabledPrefix)))
}
