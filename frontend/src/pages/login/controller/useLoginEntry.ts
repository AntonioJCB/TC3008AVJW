import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { useAuth } from '../../../controllers/useAuth'

export function useLoginEntry() {
  const navigate = useNavigate()
  const { session, profile, isPlatformAdmin, loading, error: sessionError, signIn } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (loading || !session || !profile?.esta_activo || (!profile.organizacion_id && !isPlatformAdmin)) return
    navigate(isPlatformAdmin ? '/admin' : '/home', { replace: true })
  }, [isPlatformAdmin, loading, navigate, profile, session])

  async function enterPortal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!event.currentTarget.reportValidity()) return
    const values = new FormData(event.currentTarget)
    setError(null)
    setSubmitting(true)
    try {
      await signIn(String(values.get('email') ?? '').trim(), String(values.get('password') ?? ''))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'No se pudo iniciar sesión.')
    } finally {
      setSubmitting(false)
    }
  }

  const accessError = session && !loading && (!profile?.esta_activo || (!profile.organizacion_id && !isPlatformAdmin))
    ? 'Tu cuenta no tiene acceso a una organización activa.'
    : null
  return { enterPortal, error: error ?? sessionError ?? accessError, submitting }
}
