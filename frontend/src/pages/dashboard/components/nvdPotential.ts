import type { Observation } from '../services/clientData'

export function enrichmentSources(observation: Observation): string[] {
  const explicit = Array.isArray(observation.datos.fuentes_enriquecimiento)
    ? observation.datos.fuentes_enriquecimiento : [observation.datos.fuente_enriquecimiento]
  return [...new Set(explicit.filter((value): value is string => typeof value === 'string' && Boolean(value)))]
}

export function isPotentialVulnerability(observation: Observation): boolean {
  return observation.atributo === 'cve'
    && observation.datos.verificado === false
    && enrichmentSources(observation).some(source => source === 'NVD' || source === 'OSV')
}

export const isNvdPotential = isPotentialVulnerability
