/**
 * Layout wrapper for settings pages with navigation sidebar.
 */

import { NavLink, Outlet } from 'react-router-dom'
import { User, Building2, Users, UsersRound, Layers, Server } from 'lucide-react'
import { OwlMark } from '@/features/ai/components/OwlMark'
import { cn } from '@/lib/utils'
import { useWorkspace } from '@/contexts/WorkspaceContext'

function useSettingsNavItems() {
  const { currentOrganization } = useWorkspace()
  const businessUnitLabel = currentOrganization?.businessUnitLabel ?? 'Business Units'

  return [
    {
      to: '/settings/profile',
      label: 'Profile',
      icon: User,
    },
    {
      to: '/settings/organization',
      label: 'Organization',
      icon: Building2,
    },
    {
      to: '/settings/members',
      label: 'Members',
      icon: Users,
    },
    {
      to: '/settings/teams',
      label: 'Teams',
      icon: UsersRound,
    },
    {
      to: '/settings/business-units',
      label: businessUnitLabel,
      icon: Layers,
    },
    {
      to: '/settings/systems',
      label: 'Systems',
      icon: Server,
    },
    {
      to: '/settings/ai-providers',
      label: 'AI Providers',
      icon: OwlMark,
    },
  ]
}

export function SettingsLayout() {
  const settingsNavItems = useSettingsNavItems()

  return (
    <div className="container mx-auto py-8">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      <div className="flex gap-8">
        {/* Sidebar navigation */}
        <nav className="w-48 flex-shrink-0">
          <ul className="space-y-1">
            {settingsNavItems.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                    )
                  }
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        {/* Main content area */}
        <div className="flex-1 min-w-0">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
