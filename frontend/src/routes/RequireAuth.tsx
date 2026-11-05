import { useEffect, useState, type ReactNode } from 'react'
import { Navigate } from 'react-router'
import { useAuth } from '../controllers/useAuth'
import { supabase } from '../services/supabase'
import './auth.css'

export default function RequireAuth({ children, platformOnly = false }: { children: ReactNode; platformOnly?: boolean }) {
  const { session, profile, isPlatformAdmin, loading, error, signOut } = useAuth()
  const verificationKey = session && profile ? `${session.user.id}:${session.expires_at}:${profile.id}:${profile.organizacion_id}` : null
  const [platformCheck, setPlatformCheck] = useState<{ key: string; allowed: boolean } | null>(null)
  const [clientCheck, setClientCheck] = useState<{ key: string; allowed: boolean } | null>(null)

  useEffect(() => {
    if (!platformOnly || !session || !profile || !isPlatformAdmin || !supabase) return
    const client = supabase
    let active = true
    void client.rpc('es_admin_plataforma')
      .then(({ data, error: checkError }) => {
        if (!active) return
        setPlatformCheck({
          key: `${session.user.id}:${session.expires_at}:${profile.id}:${profile.organizacion_id}`,
          allowed: !checkError && data === true,
        })
      })
    return () => { active = false }
  }, [isPlatformAdmin, platformOnly, profile, session])

  useEffect(() => {
    if (platformOnly || isPlatformAdmin || !session || !profile?.organizacion_id || !supabase) return
    const client = supabase
    let active = true
    void client.rpc('mi_organizacion_id').then(({ data, error: checkError }) => {
      if (!active) return
      setClientCheck({
        key: `${session.user.id}:${session.expires_at}:${profile.id}:${profile.organizacion_id}`,
        allowed: !checkError && data === profile.organizacion_id,
      })
    })
    return () => { active = false }
  }, [isPlatformAdmin, platformOnly, profile, session])

  if (loading) return <div className="route-status" role="status">Verificando tu sesión…</div>
  if (!session) return <Navigate to="/login" replace />
  if (error || !profile || !profile.esta_activo || (!platformOnly && !profile.organizacion_id)) {
    return (
      <main className="route-status" role="alert">
        <p>{error ?? 'Tu cuenta no tiene acceso a una organización activa.'}</p>
        <button type="button" onClick={() => { void signOut() }}>Cerrar sesión</button>
      </main>
    )
  }
  if (platformOnly && !isPlatformAdmin) return <Navigate to="/home" replace />
  if (platformOnly && platformCheck?.key !== verificationKey) {
    return <div className="route-status" role="status">Verificando permisos de administración…</div>
  }
  if (platformOnly && !platformCheck?.allowed) {
    return <main className="route-status" role="alert"><p>Tu cuenta ya no tiene permisos de administración.</p><button type="button" onClick={() => { void signOut() }}>Cerrar sesión</button></main>
  }
  if (!platformOnly && isPlatformAdmin) return <Navigate to="/admin" replace />
  if (!platformOnly && clientCheck?.key !== verificationKey) {
    return <div className="route-status" role="status">Verificando acceso al cliente…</div>
  }
  if (!platformOnly && !clientCheck?.allowed) {
    return <main className="route-status" role="alert"><p>Tu organización está deshabilitada o archivada.</p><button type="button" onClick={() => { void signOut() }}>Cerrar sesión</button></main>
  }
  return children
}
