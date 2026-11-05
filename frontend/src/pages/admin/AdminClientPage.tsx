import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ArrowLeft, Building2, LogOut, Settings2 } from 'lucide-react'
import { useNavigate, useParams } from 'react-router'
import { useAuth } from '../../controllers/useAuth'
import { ClientManager } from './AdminPortalPage'
import {
  assignUser, changeClientStatus, deleteEmptyClient, inviteUser, loadAdminData,
  loadMembers, sendPasswordReset, updateClient, updateMember,
  type AdminData, type ClientAction, type Member,
} from './adminData'
import '../dashboard/dashboard.css'
import '../dashboard/typography.css'
import '../dashboard/components/sidebar/sidebar.css'
import '../dashboard/clientPortal.css'
import './adminPortal.css'

type Confirmation = { title: string; description: string; label: string; run: () => Promise<void> }

export default function AdminClientPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { profile, signOut } = useAuth()
  const [data, setData] = useState<AdminData | null>(null)
  const [members, setMembers] = useState<Member[]>([])
  const [showUserForm, setShowUserForm] = useState(false)
  const [existingId, setExistingId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)

  const reload = useCallback(async () => {
    if (!id) return
    const [clients, users] = await Promise.all([loadAdminData(), loadMembers(id)])
    setData(clients)
    setMembers(users)
  }, [id])

  useEffect(() => {
    document.title = 'BaxterSec · Cliente'
    const timer = window.setTimeout(() => { void reload().catch((cause: unknown) => setError(message(cause))) }, 0)
    return () => window.clearTimeout(timer)
  }, [reload])

  const client = data?.clients.find((item) => item.id === id)

  async function run(action: () => Promise<void>, success: string): Promise<boolean> {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      await action()
      await reload()
      setNotice(success)
      return true
    } catch (cause) {
      setError(message(cause))
      return false
    } finally { setBusy(false) }
  }

  function confirmStatus(action: ClientAction) {
    if (!client) return
    const labels: Record<ClientAction, string> = { habilitar: 'Habilitar', deshabilitar: 'Deshabilitar', archivar: 'Archivar', restaurar: 'Restaurar' }
    setConfirmation({ title: `${labels[action]} cliente`, description: `Se actualizará el acceso de «${client.nombre}». Los datos se conservarán.`, label: labels[action], run: () => run(() => changeClientStatus(client.id, action), 'Estado del cliente actualizado.').then(() => undefined) })
  }

  function confirmDelete() {
    if (!client) return
    setConfirmation({ title: 'Eliminar cliente vacío', description: `«${client.nombre}» se borrará definitivamente. Solo se permite si no tiene cuentas ni datos operativos.`, label: 'Eliminar definitivamente', run: async () => { if (await run(() => deleteEmptyClient(client.id), 'Cliente eliminado.')) navigate('/admin') } })
  }

  async function submitUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!id) return
    const values = new FormData(event.currentTarget)
    const role = String(values.get('role')) as Member['rol']
    const existing = String(values.get('existing') ?? '')
    const ok = existing
      ? await run(() => assignUser(existing, id, role), 'Cuenta asignada al cliente.')
      : await run(() => inviteUser(id, String(values.get('name')).trim(), String(values.get('email')).trim(), role), 'Invitación enviada y cuenta asignada al cliente.')
    if (ok) setShowUserForm(false)
  }

  return <div className="dashboard-shell proposal-dashboard client-portal admin-portal">
    <aside className="sidebar" aria-label="Navegación de administración">
      <div className="brand"><div className="brand-mark" aria-hidden="true">B<small>4</small></div><span>BaxterSec</span></div>
      <nav><div className="nav-group"><span className="nav-label">Plataforma</span><button type="button" className="nav-item active" onClick={() => navigate('/admin')}><span className="nav-icon"><Building2 size={18} /></span>Clientes</button><button type="button" className="nav-item" onClick={() => navigate('/admin?seccion=configuracion')}><span className="nav-icon"><Settings2 size={18} /></span>Configuración</button></div></nav>
      <div className="sidebar-foot"><div className="avatar" aria-hidden="true">{profile?.nombre?.trim().slice(0, 2).toUpperCase() || 'BS'}</div><div className="sidebar-profile"><strong>{profile?.nombre ?? 'Administrador'}</strong><span>Plataforma</span></div><button className="sidebar-exit" type="button" aria-label="Cerrar sesión" onClick={() => { void signOut().then(() => navigate('/login', { replace: true })).catch(() => setError('No se pudo cerrar sesión.')) }}><LogOut size={17} /></button></div>
    </aside>
    <div className="dashboard-main"><header className="client-topbar"><div><span>ADMINISTRACIÓN DE PLATAFORMA</span><h1>{client?.nombre ?? 'Cliente'}</h1><p>Información general y cuentas de la empresa</p></div><button type="button" onClick={() => navigate('/admin')}><ArrowLeft size={17} /> Volver a clientes</button></header>
      <main className="dashboard-content client-content"><div className="client-section">
        {error && <div className="client-error" role="alert">{error}</div>}{notice && <div className="admin-notice" role="status">{notice}</div>}
        {!data ? <p className="client-loading" role="status">Cargando cliente…</p> : !client ? <section className="client-card"><h3>Cliente no encontrado</h3><p>Esta organización ya no está disponible.</p></section> : <>
          <div className="client-stats admin-stats"><article><span>Integrantes</span><strong>{client.integrantes}</strong><small>Cuentas activas</small></article><article><span>Escaneos</span><strong>{client.escaneos}</strong><small>Análisis registrados</small></article><article><span>Activos</span><strong>{client.activos}</strong><small>Inventario de la empresa</small></article></div>
          <ClientManager key={client.id} client={client} members={members} busy={busy} onClose={() => navigate('/admin')} onSave={(name, domain) => { void run(() => updateClient(client.id, name, domain), 'Información del cliente actualizada.') }} onStatus={confirmStatus} onDelete={confirmDelete} onMemberSave={(member) => { void run(() => updateMember(client.id, member), 'Cuenta actualizada.') }} onPasswordReset={(email) => { void run(() => sendPasswordReset(email), 'Se solicitó un enlace para cambiar la contraseña.') }} onAddUser={() => { setExistingId(''); setError(null); setShowUserForm(true) }} />
        </>}
      </div></main>
    </div>
    {showUserForm && client && <div className="admin-modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowUserForm(false) }}><div className="admin-modal admin-user-modal" role="dialog" aria-modal="true" aria-labelledby="admin-user-title"><h2 id="admin-user-title">Agregar usuario a {client.nombre}</h2><p>Envía una invitación por correo o asigna una cuenta existente sin cliente.</p>{error && <div className="client-error" role="alert">{error}</div>}<form className="admin-form" onSubmit={(event) => { void submitUser(event) }}>{!existingId && <div className="admin-fields"><label>Nombre<input name="name" minLength={2} maxLength={120} required /></label><label>Correo electrónico<input name="email" type="email" required /></label></div>}{data && data.pendingUsers.length > 0 && <label className="admin-existing-label">O asignar cuenta existente<select name="existing" defaultValue="" onChange={(event) => setExistingId(event.target.value)}><option value="">Crear con invitación</option>{data.pendingUsers.map((user) => <option key={user.id} value={user.id}>{user.nombre} · {user.correo}</option>)}</select></label>}<label className="admin-existing-label">Rol<select name="role" defaultValue="lector"><option value="lector">Lector</option><option value="analista">Analista</option><option value="admin">Admin del cliente</option></select></label><div className="admin-actions"><button type="button" onClick={() => setShowUserForm(false)}>Cancelar</button><button className="admin-primary" type="submit" disabled={busy}>Agregar usuario</button></div></form></div></div>}
    {confirmation && <div className="admin-modal-backdrop"><div className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="admin-confirm-title"><h2 id="admin-confirm-title">{confirmation.title}</h2><p>{confirmation.description}</p><div className="admin-actions"><button type="button" onClick={() => setConfirmation(null)}>Cancelar</button><button type="button" className="admin-danger" disabled={busy} onClick={() => { const action = confirmation; setConfirmation(null); void action.run() }}>{confirmation.label}</button></div></div></div>}
  </div>
}

function message(cause: unknown) { return cause instanceof Error ? cause.message : 'Ocurrió un error. Intenta de nuevo.' }
