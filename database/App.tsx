import { useEffect, useState } from 'react'
import { supabase } from './utils/supabase'

type Organization = {
  id: string
  nombre: string
  dominio_principal: string
}

export default function App() {
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadCount, setReloadCount] = useState(0)

  useEffect(() => {
    let isCurrent = true

    async function getOrganizations() {
      setLoading(true)
      setError(null)

      const { data, error: queryError } = await supabase
        .from('organizaciones')
        .select('id, nombre, dominio_principal')
        .order('nombre')

      if (!isCurrent) return

      if (queryError) {
        setError(queryError.message)
        setOrganizations([])
      } else {
        setOrganizations((data ?? []) as Organization[])
      }

      setLoading(false)
    }

    getOrganizations().catch((cause: unknown) => {
      if (!isCurrent) return

      setError(cause instanceof Error ? cause.message : 'Error inesperado al consultar Supabase.')
      setOrganizations([])
      setLoading(false)
    })

    return () => {
      isCurrent = false
    }
  }, [reloadCount])

  let connectionLabel = 'Supabase conectado'
  if (loading) connectionLabel = 'Conectando'
  else if (error) connectionLabel = 'Conexión con errores'

  function renderOrganizationContent() {
    if (loading) {
      return <output className="message">Cargando organizaciones...</output>
    }

    if (error) {
      return (
        <div className="error-state" role="alert">
          <div>
            <h2>No se pudieron cargar las organizaciones</h2>
            <p>{error}</p>
          </div>
          <button className="retry-button" onClick={() => setReloadCount((count) => count + 1)}>
            Reintentar
          </button>
        </div>
      )
    }

    if (organizations.length === 0) {
      return (
        <p className="message">
          No hay organizaciones visibles. La tabla puede estar vacía o RLS puede ocultar sus filas.
        </p>
      )
    }

    return (
      <ul className="organization-list">
        {organizations.map((organization) => (
          <li className="organization-row" key={organization.id}>
            <span className="organization-name">{organization.nombre}</span>
            <span className="organization-domain">{organization.dominio_principal}</span>
          </li>
        ))}
      </ul>
    )
  }

  return (
    <main className="page-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="BaxterSec, inicio">
          <span className="brand-mark" aria-hidden="true">B</span>
          <span>BaxterSec</span>
        </a>
        <span className="connection-indicator">
          <span className={`connection-dot${error ? ' is-error' : ''}`} />
          {connectionLabel}
        </span>
      </header>

      <section className="content" aria-labelledby="page-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">ESPACIO DE TRABAJO</p>
            <h1 id="page-title">Organizaciones</h1>
            <p className="subtitle">Dominios registrados en BaxterSec.</p>
          </div>
          {!loading && !error && (
            <span className="result-count">
              {organizations.length} {organizations.length === 1 ? 'organización' : 'organizaciones'}
            </span>
          )}
        </div>

        {renderOrganizationContent()}
      </section>
    </main>
  )
}