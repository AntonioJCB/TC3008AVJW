import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { AuthContext, type UserProfile } from './authContext'
import { supabase, supabaseConfigurationError } from '../services/supabase'
import { getThemePreference, saveThemePreference, type Theme } from '../services/themePreference'

type AuthState = {
  session: Session | null
  profile: UserProfile | null
  isPlatformAdmin: boolean
  loading: boolean
  error: string | null
  theme: Theme
}

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    session: null,
    profile: null,
    isPlatformAdmin: false,
    loading: Boolean(supabase),
    error: supabaseConfigurationError,
    theme: 'dark',
  })
  const [themeSaving, setThemeSaving] = useState(false)
  const [themeError, setThemeError] = useState<string | null>(null)
  const themeWriteInFlight = useRef(false)
  const currentUserId = useRef<string | null>(null)

  useEffect(() => {
    if (!supabase) return
    const client = supabase
    let mounted = true
    let requestId = 0

    async function loadProfile(session: Session, id: number) {
      const { data: userData, error: userError } = await client.auth.getUser(session.access_token)
      if (!mounted || id !== requestId) return
      if (userError || !userData.user) {
        setState({ session: null, profile: null, isPlatformAdmin: false, loading: false, error: 'La sesión expiró. Ingresa de nuevo.', theme: 'dark' })
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
      setState((current) => ({
        session,
        profile: profileResult.data as UserProfile | null,
        isPlatformAdmin: !platformResult.error && Boolean(platformResult.data) && Boolean(profileResult.data?.esta_activo),
        loading: false,
        error: profileResult.error ? 'No se pudo consultar tu perfil. Intenta recargar la página.' : null,
        theme: themeWriteInFlight.current && current.session?.user.id === userData.user.id
          ? current.theme
          : getThemePreference(userData.user.user_metadata),
      }))
    }

    const { data: { subscription } } = client.auth.onAuthStateChange((_event, session) => {
      requestId += 1
      if (currentUserId.current !== (session?.user.id ?? null)) {
        currentUserId.current = session?.user.id ?? null
        setThemeError(null)
      }
      if (!session) {
        setState({ session: null, profile: null, isPlatformAdmin: false, loading: false, error: null, theme: 'dark' })
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
          theme: sameUser ? current.theme : 'dark',
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

  async function setThemePreference(theme: Theme) {
    if (!supabase || !state.session || !state.profile || themeWriteInFlight.current) return
    const userId = state.session.user.id
    const previous = state.theme
    if (previous === theme) return
    themeWriteInFlight.current = true
    setThemeSaving(true)
    setThemeError(null)
    setState((current) => current.session?.user.id === userId ? { ...current, theme } : current)
    try {
      await saveThemePreference(supabase.auth, userId, theme)
    } catch {
      if (currentUserId.current === userId) {
        setState((current) => current.session?.user.id === userId ? { ...current, theme: previous } : current)
        setThemeError('No se pudo guardar el tema. Intenta de nuevo.')
      }
    } finally {
      themeWriteInFlight.current = false
      setThemeSaving(false)
    }
  }

  return (
    <AuthContext.Provider value={{ ...state, themeSaving, themeError, setThemePreference, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}
