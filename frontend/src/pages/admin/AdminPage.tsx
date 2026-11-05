import { useEffect, useState } from 'react'
import DashboardSidebar from '../dashboard/components/sidebar/DashboardSidebar'
import { useAuth } from '../../controllers/useAuth'
import { supabase } from '../../services/supabase'
import '../dashboard/dashboard.css'
import '../dashboard/typography.css'
import './admin.css'

type Organization = { id: string; nombre: string; dominio_principal: string }
type TeamMember = { id: string; nombre: string; correo: string; rol: string; esta_activo: boolean }
type DomainAuthorization = { id: string; alcance: string; expira_en: string | null; revocada_en: string | null }

export default function AdminPage() {
  const { profile } = useAuth()
  const organizationId = profile?.organizacion_id
  const [organization, setOrganization] = useState<Organization | null>(null)
  const [members, setMembers] = useState<TeamMember[]>([])
  const [authorizations, setAuthorizations] = useState<DomainAuthorization[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [checkedAt, setCheckedAt] = useState(0)

  useEffect(() => { document.title = 'BaxterSec · Administración' }, [])

  useEffect(() => {
    if (!supabase || !organizationId) return
    const client = supabase
    let active = true

    async function load() {
      const [orgResult, membersResult, authorizationsResult] = await Promise.all([
        client.from('organizaciones').select('id, nombre, dominio_principal').eq('id', organizationId).single(),
        client.from('usuarios').select('id, nombre, correo, rol, esta_activo').eq('organizacion_id', organizationId).order('nombre'),
        client.from('autorizaciones_dominio').select('id, alcance, expira_en, revocada_en').eq('organizacion_id', organizationId).order('autorizado_en', { ascending: false }),
      ])
      if (!active) return
      if (orgResult.error || membersResult.error || authorizationsResult.error) {
        setError('No se pudo cargar la información de administración.')
      } else {
        setOrganization(orgResult.data)
        setMembers(membersResult.data ?? [])
        setAuthorizations(authorizationsResult.data ?? [])
        setCheckedAt(Date.now())
        setError(null)
      }
      setLoading(false)
    }

    void load()
    return () => { active = false }
  }, [organizationId])

  return (
    <div className="dashboard-shell proposal-dashboard">
      <DashboardSidebar />
      <div className="dashboard-main">
        <main className="dashboard-content admin-content">
          <div className="eyebrow">ACCESO DE ADMINISTRADOR</div>
          <h1>Administración</h1>
          <p className="admin-lead">Organización, integrantes y autorizaciones de dominio.</p>

          {loading && <p role="status">Cargando información…</p>}
          {error && <p role="alert">{error}</p>}
          {!loading && !error && (
            <div className="admin-grid">
              <section className="admin-card" aria-labelledby="admin-org-title">
                <h2 id="admin-org-title">Organización</h2>
                <strong>{organization?.nombre}</strong>
                <p>{organization?.dominio_principal}</p>
              </section>

              <section className="admin-card" aria-labelledby="admin-team-title">
                <h2 id="admin-team-title">Equipo</h2>
                <ul>
                  {members.map((member) => (
                    <li key={member.id}>
                      <span><strong>{member.nombre}</strong><small>{member.correo}</small></span>
                      <span className="admin-tag">{member.esta_activo ? member.rol : 'inactivo'}</span>
                    </li>
                  ))}
                </ul>
              </section>

              <section className="admin-card" aria-labelledby="admin-authorizations-title">
                <h2 id="admin-authorizations-title">Autorizaciones de dominio</h2>
                {authorizations.length === 0 ? <p>No hay autorizaciones registradas.</p> : (
                  <ul>
                    {authorizations.map((authorization) => {
                      const expired = authorization.expira_en && new Date(authorization.expira_en).getTime() <= checkedAt
                      const status = authorization.revocada_en ? 'revocada' : expired ? 'vencida' : 'vigente'
                      return (
                        <li key={authorization.id}>
                          <span>{authorization.alcance}</span>
                          <span className="admin-tag">{status}</span>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
