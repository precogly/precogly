/**
 * API hooks for organizations, teams, and sharing.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type {
  Organization,
  OrganizationListItem,
  BusinessUnit,
  Team,
  TeamListItem,
  TeamMembership,
  TeamInvitation,
  MagicLink,
  InviteMemberResponse,
  JoinTeamResponse,
  AcceptInvitationResponse,
  InvitationDetailsResponse,
  MagicLinkAccessResponse,
  OrganizationMembership,
  SharedWithMe,
} from '@/features/organization/types/organization'

// Query keys
export const organizationKeys = {
  all: ['organizations'] as const,
  list: () => [...organizationKeys.all, 'list'] as const,
  detail: (id: number) => [...organizationKeys.all, 'detail', id] as const,
  members: (id: number) => [...organizationKeys.all, id, 'members'] as const,
}

export const businessUnitKeys = {
  all: ['business-units'] as const,
  list: (orgId?: number) => [...businessUnitKeys.all, 'list', orgId] as const,
  detail: (id: number) => [...businessUnitKeys.all, 'detail', id] as const,
}

export const teamKeys = {
  all: ['teams'] as const,
  list: (orgId?: number, myTeamsOnly?: boolean) =>
    [...teamKeys.all, 'list', { orgId, myTeamsOnly }] as const,
  detail: (id: number) => [...teamKeys.all, 'detail', id] as const,
  members: (id: number) => [...teamKeys.all, id, 'members'] as const,
}

export const invitationKeys = {
  all: ['team-invitations'] as const,
  list: () => [...invitationKeys.all, 'list'] as const,
  detail: (token: string) => [...invitationKeys.all, 'detail', token] as const,
}

export const magicLinkKeys = {
  all: ['magic-links'] as const,
  list: (threatModelId?: number) => [...magicLinkKeys.all, 'list', threatModelId] as const,
  access: (token: string) => [...magicLinkKeys.all, 'access', token] as const,
}

export const sharedWithMeKeys = {
  all: ['shared-with-me'] as const,
  list: () => [...sharedWithMeKeys.all, 'list'] as const,
}

// Organization queries
export function useOrganizations() {
  return useQuery({
    queryKey: organizationKeys.list(),
    queryFn: async () => {
      const response = await api.get<{ results: OrganizationListItem[] } | OrganizationListItem[]>(
        '/organizations/'
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useOrganization(id: number) {
  return useQuery({
    queryKey: organizationKeys.detail(id),
    queryFn: () => api.get<Organization>(`/organizations/${id}/`),
    enabled: id > 0,
  })
}

export function useOrganizationMembers(orgId: number) {
  return useQuery({
    queryKey: organizationKeys.members(orgId),
    queryFn: () => api.get<OrganizationMembership[]>(`/organizations/${orgId}/members/`),
    enabled: orgId > 0,
  })
}

// Business Unit queries
export function useBusinessUnits(organizationId?: number) {
  return useQuery({
    queryKey: businessUnitKeys.list(organizationId),
    queryFn: async () => {
      const url = organizationId
        ? `/business-units/?organization=${organizationId}`
        : '/business-units/'
      const response = await api.get<{ results: BusinessUnit[] } | BusinessUnit[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

// Team queries
export function useTeams(organizationId?: number, myTeamsOnly = false) {
  return useQuery({
    queryKey: teamKeys.list(organizationId, myTeamsOnly),
    queryFn: async () => {
      const params = new URLSearchParams()
      if (organizationId) params.append('organization', organizationId.toString())
      if (myTeamsOnly) params.append('my_teams', 'true')
      const queryString = params.toString()
      const url = queryString ? `/teams/?${queryString}` : '/teams/'
      const response = await api.get<{ results: TeamListItem[] } | TeamListItem[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useTeam(id: number) {
  return useQuery({
    queryKey: teamKeys.detail(id),
    queryFn: () => api.get<Team>(`/teams/${id}/`),
    enabled: id > 0,
  })
}

export function useTeamMembers(teamId: number) {
  return useQuery({
    queryKey: teamKeys.members(teamId),
    queryFn: () => api.get<TeamMembership[]>(`/teams/${teamId}/members/`),
    enabled: teamId > 0,
  })
}

// Team mutations
export function useCreateTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { organization: number; name: string; code?: string; description?: string; businessUnit?: number }) =>
      api.post<Team>('/teams/', input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.all })
    },
  })
}

export function useUpdateTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<Team> }) =>
      api.patch<Team>(`/teams/${id}/`, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.all })
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(id) })
    },
  })
}

export function useAddTeamMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ teamId, userId, role }: { teamId: number; userId: number; role: string }) =>
      api.post<TeamMembership>(`/teams/${teamId}/add-member/`, { userId, role }),
    onSuccess: (_, { teamId }) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.members(teamId) })
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(teamId) })
    },
  })
}

export function useInviteTeamMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ teamId, email, role }: { teamId: number; email: string; role: string }) =>
      api.post<InviteMemberResponse>(`/teams/${teamId}/invite-member/`, { email, role }),
    onSuccess: (_, { teamId }) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.members(teamId) })
      queryClient.invalidateQueries({ queryKey: invitationKeys.all })
    },
  })
}

export function useRemoveTeamMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ teamId, userId }: { teamId: number; userId: number }) =>
      api.post(`/teams/${teamId}/remove-member/`, { userId }),
    onSuccess: (_, { teamId }) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.members(teamId) })
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(teamId) })
    },
  })
}

export function useJoinTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (teamId: number) =>
      api.post<JoinTeamResponse>(`/teams/${teamId}/join/`),
    onSuccess: (_, teamId) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.members(teamId) })
      queryClient.invalidateQueries({ queryKey: teamKeys.all })
    },
  })
}

// Team Invitation queries and mutations
export function useTeamInvitations() {
  return useQuery({
    queryKey: invitationKeys.list(),
    queryFn: async () => {
      const response = await api.get<{ results: TeamInvitation[] } | TeamInvitation[]>(
        '/team-invitations/'
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useInvitationDetails(token: string) {
  return useQuery({
    queryKey: invitationKeys.detail(token),
    queryFn: () => api.get<InvitationDetailsResponse>(`/invite/${token}/`),
    enabled: !!token,
  })
}

export function useAcceptInvitation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (token: string) =>
      api.post<AcceptInvitationResponse>(`/invite/${token}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.all })
      queryClient.invalidateQueries({ queryKey: organizationKeys.all })
    },
  })
}

export function useRevokeInvitation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (invitationId: string) =>
      api.post(`/team-invitations/${invitationId}/revoke/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: invitationKeys.all })
    },
  })
}

// Magic Link queries and mutations
export function useMagicLinks(threatModelId?: number) {
  return useQuery({
    queryKey: magicLinkKeys.list(threatModelId),
    queryFn: async () => {
      const url = threatModelId
        ? `/magic-links/?threat_model=${threatModelId}`
        : '/magic-links/'
      const response = await api.get<{ results: MagicLink[] } | MagicLink[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useCreateMagicLink() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (threatModelId: number) =>
      api.post<MagicLink>('/magic-links/', { threat_model: threatModelId }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: magicLinkKeys.list(data.threatModel) })
    },
  })
}

export function useRevokeMagicLink() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (linkId: string) =>
      api.post(`/magic-links/${linkId}/revoke/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: magicLinkKeys.all })
    },
  })
}

// Public magic link access (no auth required - handled by backend)
export function useMagicLinkAccess(token: string) {
  return useQuery({
    queryKey: magicLinkKeys.access(token),
    queryFn: () => api.get<MagicLinkAccessResponse>(`/share/${token}/`),
    enabled: !!token,
    retry: false, // Don't retry on 404/410
  })
}

// Shared with Me queries and mutations
export function useSharedWithMe() {
  return useQuery({
    queryKey: sharedWithMeKeys.list(),
    queryFn: async () => {
      const response = await api.get<{ results: SharedWithMe[] } | SharedWithMe[]>(
        '/shared-with-me/'
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useRemoveSharedWithMe() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) =>
      api.delete(`/shared-with-me/${id}/remove/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: sharedWithMeKeys.all })
    },
  })
}

// Organization mutations
export function useUpdateOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<Organization> }) =>
      api.patch<Organization>(`/organizations/${id}/`, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: organizationKeys.all })
      queryClient.invalidateQueries({ queryKey: organizationKeys.detail(id) })
    },
  })
}

// Organization member mutations
export function useAddOrgMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId, role }: { orgId: number; userId: number; role: string }) =>
      api.post(`/organizations/${orgId}/add-member/`, { user: userId, role }),
    onSuccess: (_, { orgId }) => {
      queryClient.invalidateQueries({ queryKey: organizationKeys.members(orgId) })
    },
  })
}

export function useRemoveOrgMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId }: { orgId: number; userId: number }) =>
      api.post(`/organizations/${orgId}/remove-member/`, { user: userId }),
    onSuccess: (_, { orgId }) => {
      queryClient.invalidateQueries({ queryKey: organizationKeys.members(orgId) })
    },
  })
}

export function useUpdateOrgMemberRole() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ membershipId, role }: { membershipId: number; role: string }) =>
      api.patch<OrganizationMembership>(`/memberships/${membershipId}/`, { role }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: organizationKeys.all })
    },
  })
}

// Team mutations (additional)
export function useDeleteTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (teamId: number) => api.delete(`/teams/${teamId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: teamKeys.all })
    },
  })
}

export function useChangeTeamMemberRole() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ teamId, userId, role }: { teamId: number; userId: number; role: string }) =>
      api.post<TeamMembership>(`/teams/${teamId}/change-member-role/`, { userId, role }),
    onSuccess: (_, { teamId }) => {
      queryClient.invalidateQueries({ queryKey: teamKeys.members(teamId) })
      queryClient.invalidateQueries({ queryKey: teamKeys.detail(teamId) })
    },
  })
}

// Business Unit mutations
export function useCreateBusinessUnit() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { organization: number; name: string; code?: string; description?: string; parent?: number }) =>
      api.post<BusinessUnit>('/business-units/', input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: businessUnitKeys.all })
    },
  })
}

export function useUpdateBusinessUnit() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<BusinessUnit> }) =>
      api.patch<BusinessUnit>(`/business-units/${id}/`, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: businessUnitKeys.all })
      queryClient.invalidateQueries({ queryKey: businessUnitKeys.detail(id) })
    },
  })
}

export function useDeleteBusinessUnit() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.delete(`/business-units/${id}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: businessUnitKeys.all })
    },
  })
}
