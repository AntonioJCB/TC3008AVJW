import { supabase } from '../../../services/supabase'

export type AssistantMessage = { role: 'user' | 'assistant'; content: string }
export type AssistantReply = { respuesta: string; escaneo_id: string | null; dominio: string | null }

export async function sendAssistantMessage(messages: AssistantMessage[], scanId: string | null): Promise<AssistantReply> {
  if (!supabase) throw new Error('Supabase no está configurado.')
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Tu sesión terminó. Vuelve a iniciar sesión.')

  const baseUrl = import.meta.env.VITE_API_URL?.trim().replace(/\/$/, '') || 'http://localhost:8000'
  let response: Response
  try {
    response = await fetch(baseUrl + '/api/asistente/chat', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + session.access_token,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        mensajes: messages,
        ...(scanId ? { escaneo_id: scanId } : {}),
      }),
    })
  } catch {
    throw new Error('No se pudo conectar con el backend. Comprueba que esté iniciado.')
  }

  const result = await response.json().catch(() => null) as (Partial<AssistantReply> & { detail?: string }) | null
  if (!response.ok) {
    throw new Error(typeof result?.detail === 'string' ? result.detail : 'No se pudo obtener respuesta del asistente.')
  }
  if (typeof result?.respuesta !== 'string' || !result.respuesta.trim()) {
    throw new Error('El asistente devolvió una respuesta vacía.')
  }
  return {
    respuesta: result.respuesta,
    escaneo_id: result.escaneo_id ?? null,
    dominio: result.dominio ?? null,
  }
}
