import { LogOut } from 'lucide-react'
import { NavLink, useNavigate } from 'react-router'
import { navigation, navigationGroups } from '../../navigation'
import { useAuth } from '../../../../controllers/useAuth'
import './sidebar.css'

export default function DashboardSidebar() {
  const navigate = useNavigate()
  const { profile, isPlatformAdmin, signOut } = useAuth()

  async function leavePortal() {
    try {
      await signOut()
      navigate('/login', { replace: true })
    } catch {
      // La sesión permanece visible si Supabase no pudo cerrarla.
    }
  }

  return (
    <aside className="sidebar" aria-label="Navegación principal">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">B<small>4</small></div>
        <span>BaxterSec</span>
      </div>

      <nav>
        {navigationGroups.map((group) => (
          <div className="nav-group" key={group}>
            <span className="nav-label">{group}</span>
            {navigation.filter((item) => item.group === group).map(({ path, label, icon }) => (
              <NavLink
                key={path}
                to={path}
                end={path === '/home'}
                data-view={label}
                className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              >
                <span className="nav-icon" aria-hidden="true">{icon}</span>
                {label}
              </NavLink>
            ))}
          </div>
        ))}
        {isPlatformAdmin && (
          <div className="nav-group">
            <span className="nav-label">Administración</span>
            <NavLink to="/admin" className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
              <span className="nav-icon" aria-hidden="true">⚙</span>
              Gestión de BaxterSec
            </NavLink>
          </div>
        )}
      </nav>

      <div className="sidebar-foot">
        <div className="avatar" aria-hidden="true">{profile?.nombre?.trim().slice(0, 2).toUpperCase() || 'BS'}</div>
        <div className="sidebar-profile"><strong>{profile?.nombre || 'Usuario'}</strong><span>{profile?.rol || 'Sin rol'}</span></div>
        <button
          className="sidebar-exit"
          type="button"
          title="Salir del portal"
          aria-label="Salir del portal"
          onClick={() => { void leavePortal() }}
        >
          <LogOut size={17} strokeWidth={1.8} aria-hidden="true" />
        </button>
      </div>
    </aside>
  )
}
