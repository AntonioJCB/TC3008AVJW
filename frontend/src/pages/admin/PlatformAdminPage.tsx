import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Building2, LogOut, Plus, Search, Settings2, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router'
import { useAuth } from '../../controllers/useAuth'
import { supabase } from '../../services/supabase'
import './platform.css'

type Client = { id: string; nombre: string; dominio_principal: string; creado_en: string; integrantes: number }
type PendingUser = { id: string; nombre: string; correo: string; creado_en: string }
type Source = { nombre: string; tipo_acceso: string }
type Rule = { codigo: string; nombre: string; esta_activa: boolean }
type Section = 'clientes' | 'configuracion'

export default function PlatformAdminPage() {
  const navigate = useNavigate()
  const { profile, signOut } = useAuth()
  const [section, setSection] = useState<Section>('clientes')
  const [clients, setClients] = useState<Client[]>([])
  const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([])
  const [sources, setSources] = useState<Source[]>([])
  const [rules, setRules] = useState<Rule[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => { document.title = 'BaxterSec · Gestión de plataforma' }, [])

  const load = useCallback(async () => {
    if (!supabase) return
    const [clientResult, pendingResult, sourceResult, ruleResult] = await Promise.all([
      supabase.rpc('listar_clientes'),
      supabase.rpc('listar_usuarios_sin_cliente'),
      supabase.from('fuentes_osint').select('nombre, tipo_acceso').order('nombre'),
      supabase.from('reglas_riesgo').select('codigo, nombre, esta_activa').order('nombre'),
    ])
    if (clientResult.error || pendingResult.error || sourceResult.error || ruleResult.error) {
      setError('No se pudo cargar la administración. Revisa la conexión y la migración de plataforma.')
    } else {
      setClients((clientResult.data ?? []) as Client[])
      setPendingUsers((pendingResult.data ?? []) as PendingUser[])
      setSources(sourceResult.data ?? [])
      setRules(ruleResult.data ?? [])
      setError(null)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => { void load() }, 0)
    return () => window.clearTimeout(timer)
  }, [load])

  const filteredClients = useMemo(() => {
    const query = search.trim().toLocaleLowerCase()
    return query ? clients.filter((client) =>
      `${client.nombre} ${client.dominio_principal}`.toLocaleLowerCase().includes(query)) : clients
  }, [clients, search])

  async function createClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!supabase || !event.currentTarget.reportValidity()) return
    const form = event.currentTarget
    const values = new FormData(form)
    const name = String(values.get('name') ?? '').trim()
    const domain = String(values.get('domain') ?? '').trim().toLowerCase()
    setSaving(true)
    setError(null)
    setNotice(null)
    const { error: createError } = await supabase.rpc('crear_cliente', { p_nombre: name, p_dominio: domain })
    setSaving(false)
    if (createError) {
      setError(createError.code === '23505' ? 'Ya existe un cliente con ese dominio.' : 'No se pudo crear el cliente. Revisa el nombre y el dominio.')
      return
    }
    form.reset()
    setShowForm(false)
    setNotice(`Cliente «${name}» creado. Ya puedes preparar sus cuentas de acceso.`)
    await load()
  }

  async function assignUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!supabase || !event.currentTarget.reportValidity()) return
    const values = new FormData(event.currentTarget)
    const userId = String(values.get('user') ?? '')
    const clientId = String(values.get('client') ?? '')
    const role = String(values.get('role') ?? 'lector')
    setSaving(true)
    setError(null)
    setNotice(null)
    const { error: assignError } = await supabase.rpc('asignar_usuario_cliente', {
      p_usuario_id: userId, p_organizacion_id: clientId, p_rol: role,
    })
    setSaving(false)
    if (assignError) {
      setError('No se pudo asignar la cuenta. Comprueba que siga sin cliente y esté activa.')
      return
    }
    setNotice('Cuenta asignada. La persona podrá entrar a su portal al actualizar la sesión.')
    await load()
  }

  async function leave() {
    try {
      await signOut()
      navigate('/login', { replace: true })
    } catch {
      setError('No se pudo cerrar la sesión. Intenta de nuevo.')
    }
  }

  return <div className="platform-shell">
    <aside className="platform-sidebar" aria-label="Administración de plataforma">
      <div className="platform-brand"><span className="platform-brand-mark">B</span><span>BaxterSec<small>PLATAFORMA</small></span></div>
      <div className="platform-nav-label">GESTIÓN</div>
      <nav aria-label="Secciones de administración">
        <button type="button" className={section === 'clientes' ? 'active' : ''} onClick={() => setSection('clientes')}><Building2 size={18} /> Clientes</button>
        <button type="button" className={section === 'configuracion' ? 'active' : ''} onClick={() => setSection('configuracion')}><Settings2 size={18} /> Configuración</button>
      </nav>
      <div className="platform-sidebar-foot"><div><strong>{profile?.nombre ?? 'Administrador'}</strong><span>Administrador de plataforma</span></div><button type="button" aria-label="Cerrar sesión" onClick={() => { void leave() }}><LogOut size={18} /></button></div>
    </aside>

    <main className="platform-main">
      <header className="platform-topbar"><span>Administración / {section === 'clientes' ? 'Clientes' : 'Configuración'}</span><span className="platform-secure"><ShieldCheck size={16} /> Acceso protegido</span></header>
      <div className="platform-content">
        <div className="platform-heading"><div><div className="eyebrow">BAXTERSEC · PANEL INTERNO</div><h1>{section === 'clientes' ? 'Clientes' : 'Configuración general'}</h1><p>{section === 'clientes' ? 'Gestiona las organizaciones que usan la plataforma.' : 'Consulta los catálogos compartidos por la aplicación.'}</p></div>{section === 'clientes' && <button className="platform-primary" type="button" onClick={() => { setShowForm((open) => !open); setError(null) }}><Plus size={17} /> Nuevo cliente</button>}</div>
        {error && <div className="platform-message platform-error" role="alert">{error}</div>}
        {notice && <div className="platform-message" role="status">{notice}</div>}
        {loading ? <p className="platform-loading" role="status">Cargando datos de plataforma…</p> : section === 'clientes' ? <>
          <div className="platform-stats"><div><span>Clientes registrados</span><strong>{clients.length}</strong></div><div><span>Integrantes activos</span><strong>{clients.reduce((count, client) => count + Number(client.integrantes), 0)}</strong></div><div><span>Dominios registrados</span><strong>{clients.length}</strong></div></div>
          {showForm && <form className="platform-form" onSubmit={(event) => { void createClient(event) }}>
            <div><h2>Registrar cliente</h2><p>El dominio principal se usará como alcance base para sus análisis.</p></div>
            <label>Nombre de la organización<input name="name" minLength={2} maxLength={120} required placeholder="Ej. Acme México" /></label>
            <label>Dominio principal<input name="domain" required pattern="[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}" placeholder="ejemplo.com" autoCapitalize="none" spellCheck={false} /></label>
            <div className="platform-form-actions"><button type="button" onClick={() => setShowForm(false)}>Cancelar</button><button className="platform-primary" type="submit" disabled={saving}>{saving ? 'Guardando…' : 'Crear cliente'}</button></div>
          </form>}
          <section className="platform-card platform-pending" aria-labelledby="pending-title"><div className="platform-card-head"><div><h2 id="pending-title">Cuentas sin cliente</h2><p>Asigna cada cuenta a la organización que le corresponde.</p></div><span className="platform-count">{pendingUsers.length} pendientes</span></div>
            {pendingUsers.length === 0 ? <p className="platform-empty">Todas las cuentas activas tienen cliente asignado.</p> : <form className="platform-form platform-assign-form" onSubmit={(event) => { void assignUser(event) }}>
              <label>Cuenta<select name="user" required>{pendingUsers.map((user) => <option value={user.id} key={user.id}>{user.nombre} · {user.correo}</option>)}</select></label>
              <label>Cliente<select name="client" required defaultValue=""><option value="" disabled>Selecciona un cliente</option>{clients.map((client) => <option value={client.id} key={client.id}>{client.nombre}</option>)}</select></label>
              <label>Rol<select name="role" defaultValue="lector"><option value="lector">Lector</option><option value="analista">Analista</option><option value="admin">Admin del cliente</option></select></label>
              <div className="platform-form-actions"><button className="platform-primary" type="submit" disabled={saving || clients.length === 0}>{saving ? 'Asignando…' : 'Asignar cuenta'}</button></div>
            </form>}
          </section>
          <section className="platform-card" aria-labelledby="clients-title"><div className="platform-card-head"><div><h2 id="clients-title">Organizaciones</h2><p>Datos actuales de Supabase</p></div><label className="platform-search"><Search size={16} /><span className="sr-only">Buscar cliente</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Buscar cliente o dominio" /></label></div>
            {filteredClients.length === 0 ? <p className="platform-empty">{clients.length ? 'No hay coincidencias.' : 'Todavía no hay clientes registrados.'}</p> : <div className="platform-table-wrap"><table><thead><tr><th>Cliente</th><th>Dominio</th><th>Integrantes</th><th>Registrado</th></tr></thead><tbody>{filteredClients.map((client) => <tr key={client.id}><td><strong>{client.nombre}</strong></td><td>{client.dominio_principal}</td><td>{client.integrantes}</td><td>{new Intl.DateTimeFormat('es-MX', { dateStyle: 'medium' }).format(new Date(client.creado_en))}</td></tr>)}</tbody></table></div>}</section>
        </> : <div className="platform-config-grid">
          <section className="platform-card"><div className="platform-card-head"><div><h2>Fuentes OSINT</h2><p>Fuentes registradas en la base de datos</p></div><span className="platform-count">{sources.length}</span></div><ul className="platform-list">{sources.map((source) => <li key={source.nombre}><strong>{source.nombre}</strong><span>{source.tipo_acceso}</span></li>)}</ul></section>
          <section className="platform-card"><div className="platform-card-head"><div><h2>Reglas de riesgo</h2><p>Configuración usada por el motor de evaluación</p></div><span className="platform-count">{rules.filter((rule) => rule.esta_activa).length} activas</span></div><ul className="platform-list">{rules.map((rule) => <li key={rule.codigo}><strong>{rule.nombre}</strong><span>{rule.esta_activa ? 'Activa' : 'Inactiva'}</span></li>)}</ul></section>
        </div>}
      </div>
    </main>
  </div>
}
