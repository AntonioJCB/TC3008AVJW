import { supabase } from '../../../services/supabase'

export class ScanRequestError extends Error {
  readonly retryable: boolean

  constructor(message: string, retryable: boolean) {
    super(message)
    this.retryable = retryable
  }
}

export type ScanProgress = {
  escaneo_id: string
  estado: string
  puede_detener?: boolean
  mensaje: string
  dominio: string | null
  fuentes_ok: string[]
  fuentes_fallidas: string[]
  iniciado_en: string | null
  finalizado_en: string | null
  fuentes: {
    fuente: string
    estado: string
    error: string | null
    iniciado_en: string | null
    finalizado_en: string | null
    observaciones_generadas: number
  }[]
}

async function scanRequest<T>(path: string, method = 'GET', body?: object): Promise<T> {
  if (!supabase) throw new ScanRequestError('Supabase no está configurado.', false)
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new ScanRequestError('Tu sesión terminó. Vuelve a iniciar sesión.', false)

  const baseUrl = import.meta.env.VITE_API_URL?.trim().replace(/\/$/, '') || 'http://localhost:8000'
  let response: Response
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${session.access_token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ScanRequestError('No se pudo conectar con el backend. Comprueba que esté iniciado.', true)
  }

  const result = await response.json().catch(() => null) as (T & { detail?: string }) | null
  if (!response.ok) throw new ScanRequestError(
    typeof result?.detail === 'string' ? result.detail : 'No se pudo procesar el análisis.',
    response.status === 429 || response.status >= 500,
  )
  if (!result) throw new ScanRequestError('El backend devolvió una respuesta vacía.', true)
  return result
}

export function createScan(authorizationId: string) {
  return scanRequest<{ escaneo_id: string }>('/api/escaneos', 'POST', { autorizacion_id: authorizationId })
}

export function executeScan(scanId: string) {
  return scanRequest<ScanProgress>(`/api/escaneos/${scanId}/ejecutar`, 'POST')
}

export function getScanProgress(scanId: string) {
  return scanRequest<ScanProgress>(`/api/escaneos/${scanId}`)
}

export function stopScan(scanId: string) {
  return scanRequest<ScanProgress>(`/api/escaneos/${scanId}/detener`, 'POST')
}
