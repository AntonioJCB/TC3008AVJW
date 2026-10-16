import { NavLink } from 'react-router'
import Brand from '../../../components/Brand'
import { navigation, navigationGroups } from '../navigation'

export default function DashboardSidebar() {
  return (
    <aside className="dashboard-sidebar">
      <Brand />
      <nav className="sidebar-nav" aria-label="Navegación principal">
        {navigationGroups.map((group) => (
          <div className="sidebar-nav-group" key={group}>
            <div className="sidebar-group-label">{group}</div>
            {navigation.filter((item) => item.group === group).map(({ path, label, icon: Icon }) => (
              <NavLink key={path} to={path} end={path === '/home'} className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}>
                <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <span className="demo-avatar">D</span>
        <div><strong>Escenario demo</strong><small>Datos ficticios · Sin escaneo</small></div>
      </div>
    </aside>
  )
}
