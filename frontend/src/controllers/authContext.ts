import { createContext } from 'react'
import type { Session } from '@supabase/supabase-js'

export type UserRole = 'admin' | 'analista' | 'lector'

export type UserProfile = {
  id: string
  nombre: string
  correo: string
  organizacion_id: string | null
  rol: UserRole
  esta_activo: boolean
}

export type AuthContextValue = {
  session: Session | null
  profile: UserProfile | null
  isPlatformAdmin: boolean
  loading: boolean
  error: string | null
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
