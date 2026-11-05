import { useEffect, useState, type ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { AuthContext, type UserProfile } from './authContext'
import { supabase, supabaseConfigurationError } from '../services/supabase'

type AuthState = {
  session: Session | null
  profile: UserProfile | null
  isPlatformAdmin: boolean
  loading: boolean
  error: string | null
}

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    session: null,
    profile: null,
    isPlatformAdmin: false,
    loading: Boolean(supabase),
    error: supabaseConfigurationError,
  })

  useEffect(() => {
    if (!supabase) return
    const client = supabase
    let mounted = true
    let requestId = 0

    async function loadProfile(session: Session, id: number) {
      const { data: userData, error: userError } = await client.auth.getUser(session.access_token)
      if (!mounted || id !== requestId) return
      if (userError || !userData.user) {
        setState({ session: null, profile: null, isPlatformAdmin: false, loading: false, error: 'La sesión expiró. Ingresa de nuevo.' })
        await client.auth.signOut({ scope: 'local' })
        return
      }

      const [profileResult, platformResult] = await Promise.all([
        client.from('usuarios')
          .select('id, nombre, correo, organizacion_id, rol, esta_activo')
          .eq('id', userData.user.id).maybeSingle(),
        client.from('administradores_plataforma')
          .select('usuario_id').eq('usuario_id', userData.user.id).maybeSingle(),
      ])
      if (!mounted || id !== requestId) return
      setState({
        session,
        profile: profileResult.data as UserProfile | null,
        isPlatformAdmin: !platformResult.error && Boolean(platformResult.data) && Boolean(profileResult.data?.esta_activo),
        loading: false,
        error: profileResult.error ? 'No se pudo consultar tu perfil. Intenta recargar la página.' : null,
      })
    }

    const { data: { subscription } } = client.auth.onAuthStateChange((_event, session) => {
      requestId += 1
      if (!session) {
        setState({ session: null, profile: null, isPlatformAdmin: false, loading: false, error: null })
        return
      }
      setState((current) => {
        const sameUser = current.session?.user.id === session.user.id
        return {
          session,
          profile: sameUser ? current.profile : null,
          isPlatformAdmin: sameUser ? current.isPlatformAdmin : false,
          loading: !sameUser || !current.profile,
          error: null,
        }
      })
      const id = requestId
      // Supabase no permite esperar otra llamada del cliente dentro del callback.
      setTimeout(() => { void loadProfile(session, id) }, 0)
    })

    return () => {
      mounted = false
      requestId += 1
      subscription.unsubscribe()
    }
  }, [])

  async function signIn(email: string, password: string) {
    if (!supabase) throw new Error(supabaseConfigurationError ?? 'Supabase no está configurado.')
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw new Error('No se pudo iniciar sesión. Revisa tu correo y contraseña.')
  }

  async function signOut() {
    if (!supabase) return
    const { error } = await supabase.auth.signOut({ scope: 'local' })
    if (error) throw new Error('No se pudo cerrar la sesión. Intenta de nuevo.')
  }

  return (
    <AuthContext.Provider value={{ ...state, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}
