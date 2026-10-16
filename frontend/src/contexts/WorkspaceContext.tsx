/**
 * Workspace context for managing organization and team selection.
 * Implements progressive disclosure - hides complexity for single-org/team users.
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from 'react'
import { useOrganizations, useTeams } from '@/features/organization/api/organizations'
import type { OrganizationListItem, TeamListItem } from '@/features/organization/types/organization'

interface WorkspaceContextType {
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

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined)

// Local storage keys for persisting selection
const STORAGE_KEY_ORG = 'precogly_current_org'
const STORAGE_KEY_TEAM = 'precogly_current_team'

interface WorkspaceProviderProps {
  children: ReactNode
}

export function WorkspaceProvider({ children }: WorkspaceProviderProps) {
  const { data: organizations = [], isLoading: orgsLoading, refetch: refetchOrgs } = useOrganizations()

  const [currentOrganization, setCurrentOrgState] = useState<OrganizationListItem | null>(null)
  const [currentTeam, setCurrentTeamState] = useState<TeamListItem | null>(null)

  // Fetch teams for current organization
  const {
    data: teams = [],
    isLoading: teamsLoading,
    refetch: refetchTeams,
  } = useTeams(currentOrganization?.id, true) // myTeamsOnly = true

  // Load persisted selection on mount
  useEffect(() => {
    const savedOrgId = localStorage.getItem(STORAGE_KEY_ORG)
    const savedTeamId = localStorage.getItem(STORAGE_KEY_TEAM)

    if (organizations.length > 0 && !currentOrganization) {
      // Try to restore saved org, otherwise use first
      const savedOrg = savedOrgId
        ? organizations.find((o) => o.id === parseInt(savedOrgId, 10))
        : null
      const orgToSelect = savedOrg ?? organizations[0]
      setCurrentOrgState(orgToSelect)
    }

    if (teams.length > 0 && !currentTeam) {
      // Try to restore saved team, otherwise use default or first
      const savedTeam = savedTeamId
        ? teams.find((t) => t.id === parseInt(savedTeamId, 10))
        : null
      const defaultTeam = teams.find((t) => t.isDefault)
      const teamToSelect = savedTeam ?? defaultTeam ?? teams[0]
      setCurrentTeamState(teamToSelect)
    }
  }, [organizations, teams, currentOrganization, currentTeam])

  // Clear team when user explicitly switches orgs (not on initial load)
  const hasInitializedOrg = useRef(false)
  useEffect(() => {
    if (currentOrganization) {
      if (!hasInitializedOrg.current) {
        hasInitializedOrg.current = true
        return
      }
      setCurrentTeamState(null)
    }
  }, [currentOrganization?.id])

  const setCurrentOrganization = useCallback((org: OrganizationListItem) => {
    setCurrentOrgState(org)
    localStorage.setItem(STORAGE_KEY_ORG, org.id.toString())
    // Clear team when switching orgs
    localStorage.removeItem(STORAGE_KEY_TEAM)
  }, [])

  const setCurrentTeam = useCallback((team: TeamListItem) => {
    setCurrentTeamState(team)
    localStorage.setItem(STORAGE_KEY_TEAM, team.id.toString())
  }, [])

  const refresh = useCallback(() => {
    refetchOrgs()
    refetchTeams()
  }, [refetchOrgs, refetchTeams])

  const isSecurityTeam = currentOrganization?.myRole === 'security_team'

  const value: WorkspaceContextType = {
    organizations,
    currentOrganization,
    setCurrentOrganization,
    teams,
    currentTeam,
    setCurrentTeam,
    isMultiOrg: organizations.length > 1,
    isMultiTeam: teams.length > 1,
    isSecurityTeam,
    isLoading: orgsLoading || teamsLoading,
    refresh,
  }

  return (
    <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
  )
}

export function useWorkspace() {
  const context = useContext(WorkspaceContext)
  if (context === undefined) {
    throw new Error('useWorkspace must be used within a WorkspaceProvider')
  }
  return context
}
