/**
 * API hooks for boundaries (`/boundaries/`). A boundary joins two zones of
 * one blueprint and carries the crossing requirements (plan 4.5).
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AuthenticationType, AuthorizationType, BoundaryType } from '@/types/domain'

/** The spec's sessionManagement object, keys as stored (camelCase). */
export interface SessionManagement {
  accessTokenExpires?: boolean
  accessTokenTtl?: number
  refreshToken?: boolean
  refreshTokenExpires?: boolean
  refreshTokenTtl?: number
  idleTimeout?: number
  absoluteTimeout?: number
  userLogout?: boolean
  systemLogout?: boolean
}

/** backend/apps/systems/serializers.py BoundarySerializer */
export interface Boundary {
  id: number
  blueprint: number
  zoneA: number
  zoneAName: string
  zoneB: number
  zoneBName: string
  label: string
  description: string
  edgeId: string | null
  boundaryType: BoundaryType
  authentication: AuthenticationType[]
  authorization: AuthorizationType[]
  /** Derived: the list is not empty and has no `none` (I5). */
  requiresAuthentication: boolean
  requiresAuthorization: boolean
  dataValidation: boolean
  dataTransformation: boolean
  logging: boolean
  monitoring: boolean
  rateLimit: string
  protocols: string[]
  sessionManagement: SessionManagement
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export type UpdateBoundaryInput = Partial<
  Pick<
    Boundary,
    | 'label'
    | 'description'
    | 'boundaryType'
    | 'authentication'
    | 'authorization'
    | 'dataValidation'
    | 'dataTransformation'
    | 'logging'
    | 'monitoring'
    | 'rateLimit'
    | 'protocols'
    | 'sessionManagement'
  >
>

export const boundaryKeys = {
  all: ['boundaries'] as const,
  list: (scope: { blueprint?: number; threatModel?: string }) => [...boundaryKeys.all, scope] as const,
  detail: (boundaryId: number) => [...boundaryKeys.all, 'detail', boundaryId] as const,
}

export function useBoundaries(scope: { blueprint?: number; threatModel?: string | null }) {
  const blueprint = scope.blueprint
  const threatModel = scope.threatModel ?? undefined
  return useQuery({
    queryKey: boundaryKeys.list({ blueprint, threatModel }),
    queryFn: async () => {
      const params = new URLSearchParams()
      if (blueprint !== undefined) params.set('blueprint', String(blueprint))
      else if (threatModel) params.set('threat_model', threatModel)
      const query = params.toString()
      const response = await api.get<{ results: Boundary[] } | Boundary[]>(
        query ? `/boundaries/?${query}` : '/boundaries/'
      )
      return Array.isArray(response) ? response : response.results
    },
    enabled: blueprint !== undefined || !!threatModel,
  })
}

export function useUpdateBoundary() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ boundaryId, data }: { boundaryId: number; data: UpdateBoundaryInput }) =>
      api.patch<Boundary>(`/boundaries/${boundaryId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: boundaryKeys.all })
    },
  })
}
