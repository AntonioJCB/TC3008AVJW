const activeNames = new Set(['crt.sh', 'theHarvester', 'SpiderFoot'])

export function isActiveSource(name: string): boolean {
  return activeNames.has(name)
}
