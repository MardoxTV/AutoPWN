import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Crosshair, Shield, Settings, Cloud } from 'lucide-react'
import { clsx } from 'clsx'

const links = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/attack',    icon: Crosshair,       label: 'New Attack' },
  { to: '/tools',     icon: Shield,          label: 'Tools' },
  { to: '/azure',     icon: Cloud,           label: 'Azure Assess' },
  { to: '/settings',  icon: Settings,        label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-5 py-4 border-b border-gray-800">
        <span className="text-accent font-bold text-lg tracking-wider">AUTO</span>
        <span className="text-danger font-bold text-lg tracking-wider">PWN</span>
        <p className="text-gray-500 text-xs mt-0.5">HTB Automation Framework</p>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                isActive
                  ? 'bg-accent/10 text-accent'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-gray-800 text-gray-600 text-xs">
        v1.0.0 · For HTB use only
      </div>
    </aside>
  )
}
