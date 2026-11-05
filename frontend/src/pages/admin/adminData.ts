import { supabase } from '../../services/supabase'

export type Client = {
  id: string
  nombre: string
  dominio_principal: string
  creado_en: string
  integrantes: number
  escaneos: number
  activos: number
  autorizaciones: number
  esta_activa: boolean
  archivada_en: string | null
}
export type Member = { id: string; nombre: string; correo: string; rol: 'admin' | 'analista' | 'lector'; esta_activo: boolean }
export type PendingUser = { id: string; nombre: string; correo: string }
export type Rule = { id: string; codigo: string; nombre: string; categoria: string; severidad: string; peso: number; esta_activa: boolean }
export type Source = { nombre: string; tipo_acceso: string }
export type AdminData = { clients: Client[]; pendingUsers: PendingUser[]; rules: Rule[]; sources: Source[] }

function client() {
  if (!supabase) throw new Error('Supabase no está configurado.')
  return supabase
}

function checked(error: { message: string } | null, message: string) {
  if (error) throw new Error(message)
}

export async function loadAdminData(): Promise<AdminData> {
  const db = client()
  const [clients, pending, rules, sources] = await Promise.all([
    db.rpc('listar_clientes_admin'),
    db.rpc('listar_usuarios_sin_cliente'),
    db.from('reglas_riesgo').select('id, codigo, nombre, categoria, severidad, peso, esta_activa').order('nombre'),
    db.from('fuentes_osint').select('nombre, tipo_acceso').order('nombre'),
  ])
  checked(clients.error, 'No se pudo cargar la lista de clientes.')
  checked(pending.error, 'No se pudieron consultar las cuentas pendientes.')
  checked(rules.error, 'No se pudieron cargar las reglas de riesgo.')
  checked(sources.error, 'No se pudieron cargar las fuentes OSINT.')
  return {
    clients: (clients.data ?? []) as Client[],
    pendingUsers: (pending.data ?? []) as PendingUser[],
    rules: (rules.data ?? []) as Rule[],
    sources: (sources.data ?? []) as Source[],
  }
}

export async function loadMembers(organizationId: string): Promise<Member[]> {
  const { data, error } = await client().rpc('listar_usuarios_cliente', { p_organizacion_id: organizationId })
  checked(error, 'No se pudieron cargar las cuentas de este cliente.')
  return (data ?? []) as Member[]
}

export async function createClient(name: string, domain: string) {
  const { error } = await client().rpc('crear_cliente', { p_nombre: name, p_dominio: domain })
  checked(error, error?.code === '23505' ? 'Ese dominio ya está registrado.' : 'No se pudo crear el cliente.')
}

export async function updateClient(id: string, name: string, domain: string) {
  const { error } = await client().rpc('actualizar_cliente', { p_id: id, p_nombre: name, p_dominio: domain })
  checked(error, error?.code === '23505' ? 'Ese dominio ya está registrado.' : 'No se pudo guardar. Si cambiaste el dominio, revisa que no haya análisis pendientes o en ejecución.')
}

export type ClientAction = 'habilitar' | 'deshabilitar' | 'archivar' | 'restaurar'
export async function changeClientStatus(id: string, action: ClientAction) {
  const { error } = await client().rpc('cambiar_estado_cliente', { p_id: id, p_accion: action })
  checked(error, 'No se pudo cambiar el estado. Comprueba que no haya un análisis en ejecución.')
}

export async function deleteEmptyClient(id: string) {
  const { error } = await client().rpc('eliminar_cliente_vacio', { p_id: id })
  checked(error, 'Solo se puede eliminar definitivamente un cliente sin cuentas ni datos. Puedes archivarlo.')
}

export async function updateMember(organizationId: string, member: Member) {
  const { error } = await client().rpc('actualizar_usuario_cliente', {
    p_usuario_id: member.id,
    p_organizacion_id: organizationId,
    p_nombre: member.nombre,
    p_rol: member.rol,
    p_esta_activo: member.esta_activo,
  })
  checked(error, 'No se pudo actualizar la cuenta. Una cuenta de plataforma no se puede desactivar aquí.')
}

export async function assignUser(userId: string, organizationId: string, role: Member['rol']) {
  const { error } = await client().rpc('asignar_usuario_cliente', {
    p_usuario_id: userId, p_organizacion_id: organizationId, p_rol: role,
  })
  checked(error, 'No se pudo asignar la cuenta. Comprueba que siga activa y sin cliente.')
}

export async function inviteUser(organizationId: string, name: string, email: string, role: Member['rol']) {
  const { data: { session } } = await client().auth.getSession()
  if (!session) throw new Error('Tu sesión terminó. Vuelve a iniciar sesión.')
  const baseUrl = import.meta.env.VITE_API_URL?.trim().replace(/\/$/, '') || 'http://localhost:8000'
  const response = await fetch(`${baseUrl}/api/admin/clientes/${organizationId}/usuarios/invitar`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ nombre: name, correo: email, rol: role }),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(detail?.detail || 'No se pudo invitar al usuario. Comprueba que el backend esté disponible.')
  }
}

export async function saveRule(rule: Rule) {
  const { error } = await client().rpc('configurar_regla_riesgo', {
    p_id: rule.id, p_peso: rule.peso, p_esta_activa: rule.esta_activa,
  })
  checked(error, 'No se pudo guardar la regla de riesgo.')
}

export async function saveRules(rules: Rule[]) {
  const { error } = await client().rpc('configurar_reglas_riesgo_lote', {
    p_cambios: rules.map((rule) => ({ id: rule.id, peso: rule.peso, esta_activa: rule.esta_activa })),
  })
  checked(error, 'No se pudieron guardar las reglas. Ningún cambio fue aplicado; verifica los valores e intenta de nuevo.')
}

export async function sendPasswordReset(email: string) {
  const { error } = await client().auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/restablecer-clave`,
  })
  checked(error, 'No se pudo enviar el enlace. Revisa la configuración de correo y redirecciones de Supabase Auth.')
}
