import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Building2, LogOut, MoreHorizontal, Plus, Search, Settings2, X } from 'lucide-react'
import { useNavigate } from 'react-router'
import { useAuth } from '../../controllers/useAuth'
import InfoTip from '../dashboard/components/InfoTip'
import {
  changeClientStatus, createClient, deleteEmptyClient,
  loadAdminData, saveRules,
  type AdminData, type Client, type ClientAction, type Member,
  type Rule,
} from './adminData'
import '../dashboard/dashboard.css'
import '../dashboard/typography.css'
import '../dashboard/components/sidebar/sidebar.css'
import '../dashboard/clientPortal.css'
import './adminPortal.css'

type Section = 'clientes' | 'configuracion'
type Confirmation = { title: string; description: string; label: string; danger?: boolean; run: () => Promise<void> }
const emptyData: AdminData = { clients: [], pendingUsers: [], rules: [] }

export default function AdminPortalPage() {
  const navigate = useNavigate()
  const { profile, signOut } = useAuth()
  const [section, setSection] = useState<Section>(() => new URLSearchParams(window.location.search).get('seccion') === 'configuracion' ? 'configuracion' : 'clientes')
  const [data, setData] = useState<AdminData>(emptyData)
  const [menuId, setMenuId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const createTriggerRef = useRef<HTMLButtonElement>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)

  const reload = useCallback(async () => {
    const result = await loadAdminData()
    setData(result)
    return result
  }, [])

  useEffect(() => {
    let active = true
    const timer = window.setTimeout(() => {
      void loadAdminData().then((result) => {
        if (active) { setData(result); setError(null); setLoading(false) }
      }).catch((cause: unknown) => {
        if (active) { setError(message(cause)); setLoading(false) }
      })
    }, 0)
    return () => { active = false; window.clearTimeout(timer) }
  }, [])

  useEffect(() => { document.title = `BaxterSec · ${section === 'clientes' ? 'Clientes' : 'Configuración'}` }, [section])

  useEffect(() => {
    if (!menuId) return
    const closeOutside = (event: PointerEvent) => {
      if (event.target instanceof Element && !event.target.closest('.admin-menu-wrap')) setMenuId(null)
    }
    const closeEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuId(null) }
    document.addEventListener('pointerdown', closeOutside)
    document.addEventListener('keydown', closeEscape)
    return () => { document.removeEventListener('pointerdown', closeOutside); document.removeEventListener('keydown', closeEscape) }
  }, [menuId])

  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase()
    return data.clients.filter((client) => !query || `${client.nombre} ${client.dominio_principal}`.toLocaleLowerCase().includes(query))
  }, [data.clients, search])

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
    } finally {
      setBusy(false)
    }
  }

  async function leave() {
    try { await signOut(); navigate('/login', { replace: true }) }
    catch { setError('No se pudo cerrar sesión.') }
  }

  function confirmStatus(client: Client, action: ClientAction) {
    const labels: Record<ClientAction, string> = {
      habilitar: 'Habilitar', deshabilitar: 'Deshabilitar', archivar: 'Archivar', restaurar: 'Restaurar',
    }
    const completed: Record<ClientAction, string> = {
      habilitar: 'habilitado', deshabilitar: 'deshabilitado', archivar: 'archivado', restaurar: 'restaurado',
    }
    setConfirmation({
      title: `${labels[action]} cliente`,
      description: action === 'deshabilitar' || action === 'archivar'
        ? `Se cortará el acceso de las cuentas de «${client.nombre}». Sus datos se conservarán.`
        : `Las cuentas activas de «${client.nombre}» podrán volver a entrar.`,
      label: labels[action],
      danger: action === 'deshabilitar' || action === 'archivar',
      run: async () => { await run(() => changeClientStatus(client.id, action), `Cliente ${completed[action]}.`) },
    })
  }

  function confirmDelete(client: Client) {
    setConfirmation({
      title: 'Eliminar cliente vacío',
      description: `«${client.nombre}» se borrará definitivamente. Esta opción solo está disponible si no tiene cuentas, análisis, activos ni autorizaciones.`,
      label: 'Eliminar definitivamente', danger: true,
      run: async () => {
        await run(() => deleteEmptyClient(client.id), 'Cliente vacío eliminado.')
      },
    })
  }

  return <div className="dashboard-shell proposal-dashboard client-portal admin-portal">
    <aside className="sidebar" aria-label="Navegación de administración">
      <div className="brand"><div className="brand-mark" aria-hidden="true">B<small>4</small></div><span>BaxterSec</span></div>
      <nav>
        <div className="nav-group"><span className="nav-label">Plataforma</span>
          <button type="button" className={`nav-item${section === 'clientes' ? ' active' : ''}`} onClick={() => setSection('clientes')}><span className="nav-icon"><Building2 size={18} /></span>Clientes</button>
          <button type="button" className={`nav-item${section === 'configuracion' ? ' active' : ''}`} onClick={() => setSection('configuracion')}><span className="nav-icon"><Settings2 size={18} /></span>Configuración</button>
        </div>
      </nav>
      <div className="sidebar-foot"><div className="avatar" aria-hidden="true">{profile?.nombre?.trim().slice(0, 2).toUpperCase() || 'BS'}</div><div className="sidebar-profile"><strong>{profile?.nombre ?? 'Administrador'}</strong><span>Plataforma</span></div><button className="sidebar-exit" type="button" aria-label="Cerrar sesión" onClick={() => { void leave() }}><LogOut size={17} /></button></div>
    </aside>

    <div className="dashboard-main">
      <header className={`client-topbar${section === 'clientes' ? ' admin-clients-topbar' : ''}`}><div><span>ADMINISTRACIÓN DE PLATAFORMA</span><h1 className="sr-only">{section === 'clientes' ? 'Clientes' : 'Configuración'}</h1><p>Gestión de BaxterSec</p></div>{section === 'clientes' && <button ref={createTriggerRef} type="button" onClick={() => { setError(null); setShowCreate(true) }}><Plus size={16} /> Nuevo cliente</button>}</header>
      <main className="dashboard-content client-content">
        {error && <div className="client-error" role="alert">{error}</div>}
        {notice && <div className="admin-notice" role="status">{notice}</div>}
        {loading ? <p className="client-loading" role="status">Cargando administración…</p> : section === 'clientes' ? <div className="client-section">
          <div className="client-stats admin-stats"><article><span>Clientes activos</span><strong>{data.clients.filter((client) => client.esta_activa && !client.archivada_en).length}</strong><small>Organizaciones con acceso</small></article><article><span>Clientes deshabilitados</span><strong>{data.clients.filter((client) => !client.esta_activa && !client.archivada_en).length}</strong><small>Datos conservados</small></article><article><span>Cuentas sin cliente</span><strong>{data.pendingUsers.length}</strong><small>Pendientes de asignación</small></article></div>
          <section className="client-card"><div className="client-card-head"><div><h3>Organizaciones</h3><p>Abre un cliente para consultar su información y administrar sus cuentas.</p></div><label className="admin-search"><Search size={16} /><span className="sr-only">Buscar cliente</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Buscar cliente o dominio" /></label></div>
            {filtered.length ? <div className="client-table-wrap"><table><thead><tr><th>Cliente</th><th>Dominio</th><th>Estado</th><th>Integrantes</th><th><span className="sr-only">Acciones</span></th></tr></thead><tbody>{filtered.map((client) => <tr key={client.id}><td><strong>{client.nombre}</strong></td><td>{client.dominio_principal}</td><td><span className="client-status">{client.archivada_en ? 'Archivado' : client.esta_activa ? 'Activo' : 'Deshabilitado'}</span></td><td>{client.integrantes}</td><td><div className="admin-menu-wrap"><button className="admin-menu-trigger" type="button" aria-label={`Opciones de ${client.nombre}`} aria-expanded={menuId === client.id} onClick={() => setMenuId(menuId === client.id ? null : client.id)}><MoreHorizontal size={21} /></button>{menuId === client.id && <div className="admin-menu"><button type="button" onClick={() => navigate(`/admin/clientes/${client.id}`)}>Editar</button><button type="button" className="admin-menu-danger" disabled={Boolean(client.archivada_en) && Boolean(client.integrantes || client.escaneos || client.activos || client.autorizaciones)} title={client.archivada_en ? "El cliente ya está archivado" : undefined} onClick={() => { setMenuId(null); if (client.integrantes || client.escaneos || client.activos || client.autorizaciones) confirmStatus(client, 'archivar'); else confirmDelete(client) }}>Eliminar</button></div>}</div></td></tr>)}</tbody></table></div> : <p className="client-empty">No hay clientes que coincidan.</p>}</section>
          {data.pendingUsers.length > 0 && <section className="client-card"><h3>Cuentas sin cliente</h3><p className="client-card-description">Hay {data.pendingUsers.length} cuentas pendientes. Abre el cliente correspondiente y usa “Agregar usuario” para asignarlas.</p></section>}
        </div> : <ConfigPanel key={JSON.stringify(data.rules)} data={data} busy={busy} onSave={(rules) => run(() => saveRules(rules), 'Cambios de reglas guardados y verificados en Supabase.')} />}
      </main>
    </div>
    {showCreate && <CreateClientDialog busy={busy} error={error} onCancel={() => { setShowCreate(false); window.setTimeout(() => createTriggerRef.current?.focus(), 0) }} onSubmit={(name, domain) => { void (async () => { if (await run(() => createClient(name, domain), 'Cliente creado.')) { setShowCreate(false); window.setTimeout(() => createTriggerRef.current?.focus(), 0) } })() }} />}
    {confirmation && <div className="admin-modal-backdrop" role="presentation"><div className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="admin-confirm-title"><h2 id="admin-confirm-title">{confirmation.title}</h2><p>{confirmation.description}</p><div className="admin-actions"><button type="button" onClick={() => setConfirmation(null)}>Cancelar</button><button type="button" className={confirmation.danger ? 'admin-danger' : 'admin-primary'} disabled={busy} onClick={() => { const action = confirmation; setConfirmation(null); void action.run() }}>{confirmation.label}</button></div></div></div>}
  </div>
}

function message(cause: unknown) { return cause instanceof Error ? cause.message : 'Ocurrió un error. Intenta de nuevo.' }

function CreateClientDialog({ busy, error, onCancel, onSubmit }: { busy: boolean; error: string | null; onCancel: () => void; onSubmit: (name: string, domain: string) => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = dialogRef.current
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    dialog?.showModal()
    return () => { if (dialog?.open) dialog.close(); document.body.style.overflow = previousOverflow }
  }, [])
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const values = new FormData(event.currentTarget)
    const name = String(values.get('name') ?? '').trim()
    const domain = String(values.get('domain') ?? '').trim().toLowerCase()
    const nameInput = event.currentTarget.elements.namedItem('name') as HTMLInputElement
    const domainInput = event.currentTarget.elements.namedItem('domain') as HTMLInputElement
    if (name.length < 2) { nameInput.setCustomValidity('Escribe un nombre de al menos dos caracteres.'); nameInput.reportValidity(); return }
    if (domain.split('.').some((label) => label.length > 63)) { domainInput.setCustomValidity('Cada parte del dominio debe tener hasta 63 caracteres.'); domainInput.reportValidity(); return }
    onSubmit(name, domain)
  }
  return <dialog ref={dialogRef} className="admin-create-dialog" aria-labelledby="admin-create-title" aria-describedby="admin-create-description" onCancel={(event) => { event.preventDefault(); if (!busy) onCancel() }} onMouseDown={(event) => { if (event.target !== event.currentTarget || busy) return; const bounds = event.currentTarget.getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) onCancel() }}>
    <form className="admin-form admin-create-card" onSubmit={submit}>
    <div className="admin-create-head"><div><span className="eyebrow">NUEVA ORGANIZACIÓN</span><h2 id="admin-create-title">Registrar cliente</h2><p id="admin-create-description">Identifica a la empresa y define el dominio que se usará como alcance base en futuros análisis autorizados.</p></div><button type="button" className="admin-create-close" aria-label="Cerrar registro de cliente" onClick={onCancel} disabled={busy}><X size={19} /></button></div>
    <div className="admin-create-fields">
      <label><span>Nombre del cliente</span><input name="name" minLength={2} maxLength={120} autoComplete="organization" placeholder="Nombre de la empresa" onInput={(event) => event.currentTarget.setCustomValidity('')} autoFocus required /><small>Entre 2 y 120 caracteres.</small></label>
      <label><span>Dominio principal</span><input name="domain" maxLength={253} pattern="[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:[.][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+" placeholder="ejemplo.com" autoCapitalize="none" spellCheck={false} onInput={(event) => event.currentTarget.setCustomValidity('')} required /><small>Solo el dominio, sin protocolo ni rutas. Cada análisis requerirá autorización.</small></label>
    </div>
    {error && <div className="client-error admin-create-error" role="alert">{error}</div>}
    <div className="admin-create-footer"><p>Podrás agregar cuentas y autorizaciones después de crear el cliente.</p><div className="admin-actions"><button type="button" onClick={onCancel} disabled={busy}>Cancelar</button><button className="admin-primary" type="submit" disabled={busy}>{busy ? 'Creando…' : 'Crear cliente'}</button></div></div>
    </form>
  </dialog>
}

export function ClientManager({ client, members, busy, onSave, onStatus, onDelete, onMemberSave, onPasswordReset, onAddUser }: {
  client: Client; members: Member[]; busy: boolean;
  onSave: (name: string, domain: string) => void; onStatus: (action: ClientAction) => void;
  onDelete: () => void; onMemberSave: (member: Member) => void; onPasswordReset: (email: string) => void; onAddUser: () => void;
}) {
  const [name, setName] = useState(client.nombre)
  const [domain, setDomain] = useState(client.dominio_principal)
  const canDelete = Number(client.integrantes) === 0 && Number(client.escaneos) === 0 && Number(client.activos) === 0 && Number(client.autorizaciones) === 0
  const status = client.archivada_en ? 'Archivado' : client.esta_activa ? 'Activo' : 'Deshabilitado'
  return <section className="client-card admin-manager"><div className="admin-manager-head"><div><span className="eyebrow">CLIENTE SELECCIONADO</span><h3>{client.nombre}</h3><span className={`admin-state-badge${client.esta_activa && !client.archivada_en ? ' active' : ''}`}>{status}</span></div></div>
    <div className="admin-manager-summary"><div><span>DOMINIO PRINCIPAL</span><strong>{client.dominio_principal}</strong></div><div><span>REGISTRADO</span><strong>{new Date(client.creado_en).toLocaleDateString('es-MX', { dateStyle: 'medium' })}</strong></div></div>
    <div className="admin-manager-grid">
      <section className="admin-manager-panel admin-manager-profile"><div className="admin-panel-heading"><span className="eyebrow">01 · DATOS</span><div className="admin-panel-title"><h4>Información del cliente</h4><InfoTip label="información del cliente" text="Datos de identificación y dominio para los análisis." /></div></div><form className="admin-form" onSubmit={(event) => { event.preventDefault(); onSave(name.trim(), domain.trim().toLowerCase()) }}><div className="admin-fields"><label>Nombre<input value={name} onChange={(event) => setName(event.target.value)} minLength={2} maxLength={120} required disabled={Boolean(client.archivada_en)} /></label><label>Dominio principal<input value={domain} onChange={(event) => setDomain(event.target.value)} maxLength={253} pattern="[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:[.][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+" required disabled={Boolean(client.archivada_en)} /></label></div><p className="admin-scope-note">Cambiar el dominio no amplía las autorizaciones existentes. No se permite hacerlo con análisis pendientes o en ejecución.</p><div className="admin-actions"><button className="admin-primary" type="submit" disabled={busy || Boolean(client.archivada_en) || name.trim() === client.nombre && domain.trim().toLowerCase() === client.dominio_principal}>Guardar cambios</button></div></form></section>
      <section className="admin-manager-panel admin-management-actions"><div className="admin-panel-heading"><span className="eyebrow">02 · ACCESO</span><div className="admin-panel-title"><h4>Estado del cliente</h4><InfoTip label="estado del cliente" text="Controla el acceso sin perder el historial de la organización." /></div></div><div className="admin-access-state"><span>Estado actual</span><strong>{status}</strong>{!client.esta_activa && !client.archivada_en && <button type="button" onClick={() => onStatus('habilitar')} disabled={busy}>Habilitar cliente</button>}{client.archivada_en && <button type="button" onClick={() => onStatus('restaurar')} disabled={busy}>Restaurar cliente</button>}</div><div className="admin-sensitive-actions"><span className="eyebrow">ACCIONES SENSIBLES</span><p>Deshabilitar corta el acceso; archivar retira al cliente del trabajo diario. Sus datos permanecen.</p><div className="admin-actions">{!client.archivada_en && <>{client.esta_activa && <button type="button" className="admin-danger-outline" onClick={() => onStatus('deshabilitar')} disabled={busy}>Deshabilitar</button>}<button type="button" className="admin-danger-outline" onClick={() => onStatus('archivar')} disabled={busy}>Archivar</button></>}{canDelete && <button type="button" className="admin-danger-outline" onClick={onDelete} disabled={busy}>Eliminar cliente vacío</button>}</div></div></section>
    </div>
    <section className="admin-manager-panel admin-members"><div className="admin-card-toolbar"><div className="admin-panel-heading"><span className="eyebrow">03 · CUENTAS</span><div className="admin-panel-title"><h4>Cuentas del cliente <span className="admin-count">{members.length}</span></h4><InfoTip label="cuentas del cliente" text="Administra roles, acceso y recuperación de las cuentas asociadas." /></div></div><button type="button" className="admin-primary admin-add-user" onClick={onAddUser} disabled={busy || Boolean(client.archivada_en)}><Plus size={17} /> Agregar usuario</button></div>{members.length ? members.map((member) => <MemberEditor key={member.id} member={member} busy={busy} onSave={onMemberSave} onPasswordReset={onPasswordReset} />) : <p className="client-empty">Este cliente todavía no tiene cuentas.</p>}</section>
  </section>
}

function MemberEditor({ member, busy, onSave, onPasswordReset }: { member: Member; busy: boolean; onSave: (member: Member) => void; onPasswordReset: (email: string) => void }) {
  const [name, setName] = useState(member.nombre)
  const [role, setRole] = useState(member.rol)
  const [active, setActive] = useState(member.esta_activo)
  return <form className="admin-member" onSubmit={(event) => { event.preventDefault(); onSave({ ...member, nombre: name.trim(), rol: role, esta_activo: active }) }}><div><strong>{member.correo}</strong><span>{member.esta_activo ? 'Cuenta activa' : 'Cuenta deshabilitada'}</span></div><div className="admin-member-fields"><label>Nombre<input value={name} onChange={(event) => setName(event.target.value)} minLength={2} maxLength={120} required /></label><label>Rol<select value={role} onChange={(event) => setRole(event.target.value as Member['rol'])}><option value="lector">Lector</option><option value="analista">Analista</option><option value="admin">Admin del cliente</option></select></label><label className="admin-check"><input type="checkbox" checked={active} onChange={(event) => setActive(event.target.checked)} /> Activa</label></div><div className="admin-actions"><button type="button" onClick={() => onPasswordReset(member.correo)} disabled={busy}>Enviar cambio de contraseña</button><button className="admin-primary" type="submit" disabled={busy}>Guardar cuenta</button></div></form>
}

type RuleDraft = Omit<Rule, 'peso'> & { peso: string }

function ConfigPanel({ data, busy, onSave }: { data: AdminData; busy: boolean; onSave: (rules: Rule[]) => Promise<boolean> }) {
  const [drafts, setDrafts] = useState<RuleDraft[]>(() => data.rules.map((rule) => ({ ...rule, peso: String(rule.peso) })))
  const [weightError, setWeightError] = useState<string | null>(null)
  const changed = drafts.filter((rule) => { const original = data.rules.find((item) => item.id === rule.id); return original && (rule.peso !== String(original.peso) || rule.esta_activa !== original.esta_activa) })
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const invalid = drafts.find((rule) => !/^\d{1,3}$/.test(rule.peso) || Number(rule.peso) > 100)
    if (invalid) { setWeightError(`El peso de ${invalid.codigo} debe ser un entero entre 0 y 100.`); return }
    setWeightError(null)
    if (changed.length && await onSave(changed.map((rule) => ({ ...rule, peso: Number(rule.peso) })))) {
      setDrafts((current) => current.map((rule) => ({ ...rule, peso: String(Number(rule.peso)) })))
    }
  }
  return <div className="client-section">
    <div className="client-stats admin-stats admin-rule-stats">
      <article><span>Activas en catálogo</span><strong>{data.rules.filter((rule) => rule.esta_activa).length}</strong><small>Guardadas en Supabase</small></article>
      <article><span>Reglas totales</span><strong>{data.rules.length}</strong><small>Registradas en el catálogo</small></article>
    </div>
    <section className="client-card"><form onSubmit={(event) => { void save(event) }}>
      <div className="admin-card-toolbar"><div><h3>Reglas de riesgo</h3><p className="client-card-description">El peso y la activación se guardan en Supabase y se leen en los análisis nuevos. Las reglas sin evaluador o retiradas no puntúan; los resultados históricos se conservan.</p></div>{changed.length > 0 && <button className="admin-primary admin-save-all" type="submit" disabled={busy}>Guardar cambios ({changed.length})</button>}</div>
      {weightError && <p className="admin-runtime-error" role="alert">{weightError}</p>}
      <div className="admin-rule-list">{drafts.map((rule) => <RuleEditor key={rule.id} rule={rule} onChange={(next) => { setWeightError(null); setDrafts((current) => current.map((item) => item.id === next.id ? next : item)) }} />)}</div>
    </form></section>
  </div>
}

function RuleEditor({ rule, onChange }: { rule: RuleDraft; onChange: (rule: RuleDraft) => void }) {
  return <div className="admin-rule"><div><strong>{rule.nombre}</strong><span>{rule.codigo} · {rule.categoria} · {rule.severidad}</span></div><label>Peso<input type="number" min={0} max={100} step={1} value={rule.peso} onChange={(event) => onChange({ ...rule, peso: event.target.value })} required /></label><label className="admin-check"><input type="checkbox" checked={rule.esta_activa} onChange={(event) => onChange({ ...rule, esta_activa: event.target.checked })} /> Activa en catálogo</label></div>
}
