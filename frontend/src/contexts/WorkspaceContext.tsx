/**
 * Workspace context for managing organization and team selection.
 * Implements progressive disclosure - hides complexity for single-org/team users.
 */

import { createContext, useContext } from 'react'
import type { OrganizationListItem, TeamListItem } from '@/features/organization/types/organization'

export interface WorkspaceContextType {
  // Organizations
  organizations: OrganizationListItem[]
  currentOrganization: OrganizationListItem | null
  setCurrentOrganization: (org: OrganizationListItem) => void

  // Teams
  teams: TeamListItem[]
  currentTeam: TeamListItem | null
  setCurrentTeam: (team: TeamListItem) => void

  // Progressive disclosure flags
  isMultiOrg: boolean
  isMultiTeam: boolean

  // Role-based access
  isSecurityTeam: boolean

  // Loading state
  isLoading: boolean

  // Refresh function
  refresh: () => void
}

export const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined)

export function useWorkspace() {
  const context = useContext(WorkspaceContext)
  if (context === undefined) {
    throw new Error('useWorkspace must be used within a WorkspaceProvider')
  }
  return context
}
