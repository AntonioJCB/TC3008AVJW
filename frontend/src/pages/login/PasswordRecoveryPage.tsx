import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import Brand from '../../components/Brand'
import { supabase } from '../../services/supabase'
import './passwordRecovery.css'

export default function PasswordRecoveryPage() {
  const [verifying, setVerifying] = useState(true)
  const [allowed, setAllowed] = useState(false)
  const [saving, setSaving] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    document.title = 'BaxterSec · Cambiar contraseña'
    let active = true
    const timer = window.setTimeout(() => {
      void supabase?.auth.getUser().then(({ data, error: authError }) => {
        if (!active) return
        setAllowed(!authError && Boolean(data.user))
        setVerifying(false)
      })
      if (!supabase) setVerifying(false)
    }, 0)
    return () => { active = false; window.clearTimeout(timer) }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!supabase || !event.currentTarget.reportValidity()) return
    const values = new FormData(event.currentTarget)
    const password = String(values.get('password') ?? '')
    const repeated = String(values.get('repeat') ?? '')
    if (password !== repeated) { setError('Las contraseñas no coinciden.'); return }
    setSaving(true)
    setError(null)
    const { error: updateError } = await supabase.auth.updateUser({ password })
    if (updateError) {
      setError('No se pudo cambiar la contraseña. Pide un enlace nuevo e inténtalo de nuevo.')
    } else {
      await supabase.auth.signOut({ scope: 'local' })
      setDone(true)
    }
    setSaving(false)
  }

  return <div className="site-shell recovery-shell"><header className="site-header"><Brand /></header><main className="recovery-card"><div className="eyebrow">SEGURIDAD DE CUENTA</div><h1>Cambiar contraseña</h1>{verifying ? <p role="status">Verificando el enlace…</p> : done ? <><p>Tu contraseña se actualizó. Inicia sesión con la nueva.</p><Link className="recovery-link" to="/login">Ir al inicio de sesión</Link></> : !allowed ? <><p role="alert">El enlace no es válido o expiró. Solicita uno nuevo al administrador.</p><Link to="/login">Volver al inicio de sesión</Link></> : <form onSubmit={(event) => { void submit(event) }}><label>Nueva contraseña<input type="password" name="password" minLength={8} autoComplete="new-password" required /></label><label>Repetir contraseña<input type="password" name="repeat" minLength={8} autoComplete="new-password" required /></label>{error && <p className="recovery-error" role="alert">{error}</p>}<button type="submit" disabled={saving}>{saving ? 'Guardando…' : 'Guardar contraseña'}</button></form>}</main></div>
}
