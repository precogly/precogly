/**
 * API hooks for components and zones. Both belong to a blueprint
 * (`?blueprint=` narrows; `?threat_model=` covers every blueprint).
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ComponentKind, ZoneType } from '@/types/domain'

// Types

export interface ComponentLibraryItem {
  id: number
  slug?: string
  qualifiedSlug?: string
  name: string
  category: string
  /** Spec asset type; blank means "derive from the category". */
  kind?: ComponentKind | ''
  effectiveKind?: ComponentKind
  componentType: string
  provider: string | null
  sourcePackName: string | null
  sourcePackSlug: string | null
}

/** backend/apps/systems/serializers.py ZoneSerializer */
export interface Zone {
  id: number
  blueprint: number
  name: string
  zoneType: ZoneType
  /** 0 to 100, or null when not set (F13). */
  trustLevel: number | null
  description: string
  parent: number | null
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

/** @deprecated Use `Zone`. */
export type TrustZone = Zone

/** backend/apps/systems/serializers.py OrgsystemComponentSerializer */
export interface OrgsystemComponent {
  id: number
  name: string
  description: string
  category: string
  /** Spec asset type; blank means "derive from the category". */
  kind: ComponentKind | ''
  effectiveKind: ComponentKind
  actorType: string
  dataStoreType: string
  dataSensitivityLevel?: string
  /** The inventory system this system asset stands for (H5). */
  orgsystem: number | null
  componentLibrary: number | null
  componentLibraryName: string | null
  zone: number | null
  sourceIntegration: number | null
  blueprint: number
  threatModel: number | null
  parentComponent: number | null
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface CreateComponentInput {
  name: string
  description?: string
  category: string
  kind?: ComponentKind | ''
  componentLibrary?: number | null
  blueprint: number
  zone?: number | null
  parentComponent?: number | null
  orgsystem?: number | null
}

// Query keys

export const componentKeys = {
  all: ['components'] as const,
  library: ['component-library-raw'] as const,
  analysisComponents: (threatModelId: string) =>
    [...componentKeys.all, 'analysis', threatModelId] as const,
}

export const zoneKeys = {
  all: ['zones'] as const,
  list: (scope: { blueprint?: number; threatModel?: string }) => [...zoneKeys.all, scope] as const,
}

// Query Hooks

/**
 * Fetch all components from the component library.
 * Optionally filtered by a threat model's connected packs.
 */
export function useComponentLibrary(threatModelId?: string) {
  return useQuery({
    queryKey: [...componentKeys.library, threatModelId],
    queryFn: async () => {
      const params = threatModelId ? `?threat_model=${threatModelId}` : ''
      const response = await api.get<{ results: ComponentLibraryItem[] } | ComponentLibraryItem[]>(
        `/component-library/${params}`
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

/**
 * Fetch the components of a threat model (every blueprint), canvas or not.
 */
export function useAnalysisComponents(threatModelId: string | null) {
  return useQuery({
    queryKey: componentKeys.analysisComponents(threatModelId ?? ''),
    queryFn: async () => {
      const response = await api.get<{ results: OrgsystemComponent[] } | OrgsystemComponent[]>(
        `/components/?threat_model=${threatModelId}`
      )
      return Array.isArray(response) ? response : response.results
    },
    enabled: !!threatModelId,
  })
}

/**
 * Zones of a blueprint (`/zones/?blueprint=`), or of every blueprint of a
 * threat model (`/zones/?threat_model=`).
 */
export function useZones(scope: { blueprint?: number; threatModel?: string | null }) {
  const blueprint = scope.blueprint
  const threatModel = scope.threatModel ?? undefined
  return useQuery({
    queryKey: zoneKeys.list({ blueprint, threatModel }),
    queryFn: async () => {
      const params = new URLSearchParams()
      if (blueprint !== undefined) params.set('blueprint', String(blueprint))
      else if (threatModel) params.set('threat_model', threatModel)
      const query = params.toString()
      const response = await api.get<{ results: Zone[] } | Zone[]>(query ? `/zones/?${query}` : '/zones/')
      return Array.isArray(response) ? response : response.results
    },
    enabled: blueprint !== undefined || !!threatModel,
  })
}

// Mutation Hooks

/**
 * Create an analysis-only component (on a blueprint, not on a canvas).
 */
export function useCreateAnalysisComponent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateComponentInput) => api.post<OrgsystemComponent>('/components/', data),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: componentKeys.all })
      if (created.threatModel !== null) {
        queryClient.invalidateQueries({
          queryKey: componentKeys.analysisComponents(String(created.threatModel)),
        })
        queryClient.invalidateQueries({
          queryKey: ['threat-model-threats', String(created.threatModel)],
        })
      }
    },
  })
}

export function useUpdateComponent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ componentId, data }: { componentId: number; data: Partial<CreateComponentInput> }) =>
      api.patch<OrgsystemComponent>(`/components/${componentId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: componentKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

export function useCreateZone() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      blueprint: number
      name: string
      zoneType?: ZoneType
      trustLevel?: number | null
      description?: string
      parent?: number | null
    }) => api.post<Zone>('/zones/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: zoneKeys.all })
    },
  })
}
