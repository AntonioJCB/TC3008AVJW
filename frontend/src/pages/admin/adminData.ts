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
export type AdminData = { clients: Client[]; pendingUsers: PendingUser[]; rules: Rule[] }

function client() {
  if (!supabase) throw new Error('Supabase no está configurado.')
  return supabase
}

function checked(error: { message: string } | null, message: string) {
  if (error) throw new Error(message)
}

export async function loadAdminData(): Promise<AdminData> {
  const db = client()
  const [clients, pending, rules] = await Promise.all([
    db.rpc('listar_clientes_admin'),
    db.rpc('listar_usuarios_sin_cliente'),
    db.from('reglas_riesgo').select('id, codigo, nombre, categoria, severidad, peso, esta_activa').order('nombre'),
  ])
  checked(clients.error, 'No se pudo cargar la lista de clientes.')
  checked(pending.error, 'No se pudieron consultar las cuentas pendientes.')
  checked(rules.error, 'No se pudieron cargar las reglas de riesgo.')
  return {
    clients: (clients.data ?? []) as Client[],
    pendingUsers: (pending.data ?? []) as PendingUser[],
    rules: (rules.data ?? []) as Rule[],
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
  if (!rules.length) return
  if (rules.some((rule) => !Number.isInteger(rule.peso) || rule.peso < 0 || rule.peso > 100)) {
    throw new Error('Cada peso debe ser un número entero entre 0 y 100.')
  }
  const db = client()
  const { error } = await db.rpc('configurar_reglas_riesgo_lote', {
    p_cambios: rules.map((rule) => ({ id: rule.id, peso: rule.peso, esta_activa: rule.esta_activa })),
  })
  checked(error, 'No se confirmó el guardado de las reglas. Recarga los valores antes de reintentarlo.')
  const { data, error: readError } = await db.from('reglas_riesgo')
    .select('id, peso, esta_activa').in('id', rules.map((rule) => rule.id))
  if (readError || !data) throw new Error('El guardado se envió, pero no se pudo verificar en Supabase. Recarga la página antes de repetirlo.')
  const saved = new Map(data.map((rule) => [rule.id, rule]))
  if (rules.some((rule) => {
    const current = saved.get(rule.id)
    return !current || current.peso !== rule.peso || current.esta_activa !== rule.esta_activa
  })) throw new Error('Los valores leídos de Supabase no coinciden con los cambios solicitados. Recarga antes de repetir el guardado.')
}

export async function sendPasswordReset(email: string) {
  const { error } = await client().auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/restablecer-clave`,
  })
  checked(error, 'No se pudo enviar el enlace. Revisa la configuración de correo y redirecciones de Supabase Auth.')
}
