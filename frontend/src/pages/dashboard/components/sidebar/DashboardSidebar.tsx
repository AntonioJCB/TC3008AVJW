import { NavLink } from 'react-router'
import { navigation, navigationGroups } from '../../navigation'
import './sidebar.css'

export default function DashboardSidebar() {
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
      </nav>

      <div className="sidebar-foot">
        <div className="avatar" aria-hidden="true">TC</div>
        <div><strong>Analista OSINT</strong><span>Acceso autorizado</span></div>
      </div>
    </aside>
  )
}