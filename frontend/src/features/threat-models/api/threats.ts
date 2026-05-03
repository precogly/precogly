/**
 * API hooks for threat workflow endpoints.
 */

import { useQuery, useMutation, useQueryClient, skipToken } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ComponentThreat, ComponentThreatCountermeasure, CountermeasureStatus } from '@/features/dfd-editor/types/threat-analysis'
import type { TaxonomyEntry } from '@/types/domain'

// Backend countermeasure status (aligned with frontend CountermeasureStatus)
type BackendCountermeasureStatus = 'platform' | 'gap' | 'planned' | 'verified' | 'waived'

// Types
export interface ComponentInstanceThreat {
  id: number
  component: number
  componentName: string
  threatLibrary: number | null
  threatName: string
  threatNameDisplay?: string  // read field from serializer (threat_name_display)
  taxonomyEntries?: TaxonomyEntry[]
  inherentSeverity: string
  residualSeverity: string
  status: 'exposed' | 'addressable' | 'mitigated'
  severityScoringMetadata: Record<string, unknown>
  isDismissed: boolean
  dismissalReason: string
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
  /** Populated on list/detail when nested serialization is enabled */
  countermeasures?: ComponentInstanceCountermeasure[]
}

export interface CountermeasureLibraryItem {
  id: number
  name: string
  description?: string
  controlType: string
  cost: string
  defaultStatus?: string
  sourcePackName: string | null
  sourcePackSlug: string | null
}

export interface ThreatLibraryItem {
  id: number
  name: string
  description?: string  // Optional for defensive programming
  taxonomyEntries?: TaxonomyEntry[]
  sourcePackName: string | null
  sourcePackSlug: string | null
}

export interface ComponentInstanceCountermeasure {
  id: number
  instanceThreat: number
  countermeasureLibrary: number
  countermeasureName: string
  countermeasureNameDisplay?: string | null
  countermeasureDescription?: string
  controlType?: string
  controlTypeDisplay?: string
  effectiveness?: number | null
  status: BackendCountermeasureStatus
  priority: string
  verifiedBy: number | null
  verifiedByEmail: string | null
  evidenceUrl: string
  requiredForRelease: boolean
  assignedOwner: number | null
  assignedOwnerEmail: string | null
  formatMetadata: Record<string, unknown>
  displayOrder?: number
  isInherited?: boolean
  inheritedFromComponentName?: string
  inheritedFromZoneName?: string
  createdAt: string
  updatedAt: string
}

export interface GenerateThreatsResponse {
  createdCount: number
  existingCount: number
  total: number
  message: string
}

export interface SuggestedCountermeasuresResponse {
  threatId: number
  threatName: string
  suggested: CountermeasureLibraryItem[]
  applied: CountermeasureLibraryItem[]
  suggestedCount: number
  appliedCount: number
}

export interface ApplyCountermeasureResponse {
  countermeasure: ComponentInstanceCountermeasure
  message: string
}

export interface RecalculateStatusResponse {
  threatId: number
  oldStatus: string
  newStatus: string
  message: string
}

// Query keys
export const threatKeys = {
  all: ['threats'] as const,
  componentThreats: (componentId: number) => [...threatKeys.all, 'component', componentId] as const,
  threatCountermeasures: (threatId: number) => [...threatKeys.all, 'countermeasures', threatId] as const,
  suggestedCountermeasures: (threatId: number) => [...threatKeys.all, 'suggested', threatId] as const,
  threatLibrary: ['threat-library'] as const,
  countermeasureLibrary: ['countermeasure-library'] as const,
}

// Query Hooks

/**
 * Fetch threats for a specific component.
 */
export function useComponentThreats(componentId: number | null) {
  return useQuery({
    queryKey: threatKeys.componentThreats(componentId!),
    queryFn: async () => {
      const response = await api.get<{ results: ComponentInstanceThreat[] } | ComponentInstanceThreat[]>(
        `/component-threats/?component=${componentId}`
      )
      return Array.isArray(response) ? response : response.results
    },
    enabled: componentId !== null,
  })
}

/**
 * Fetch suggested countermeasures for a threat instance.
 */
export function useSuggestedCountermeasures(threatId: number | null) {
  return useQuery({
    queryKey: threatKeys.suggestedCountermeasures(threatId!),
    queryFn: () => api.get<SuggestedCountermeasuresResponse>(
      `/component-threats/${threatId}/suggested_countermeasures/`
    ),
    enabled: threatId !== null,
  })
}

/**
 * Fetch all threats from the threat library.
 */
export function useThreatLibrary() {
  return useQuery({
    queryKey: threatKeys.threatLibrary,
    queryFn: async () => {
      const response = await api.get<{ results: ThreatLibraryItem[] } | ThreatLibraryItem[]>(
        '/threat-library/'
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

/**
 * Fetch all countermeasures from the countermeasure library.
 * Optionally filter by applicable threat library ID.
 */
export function useCountermeasureLibrary(threatLibraryId?: number | null) {
  return useQuery({
    queryKey: [...threatKeys.countermeasureLibrary, threatLibraryId],
    queryFn: async () => {
      const url = threatLibraryId
        ? `/countermeasure-library/?applicable_threats=${threatLibraryId}`
        : '/countermeasure-library/'
      const response = await api.get<{ results: CountermeasureLibraryItem[] } | CountermeasureLibraryItem[]>(url)
      return Array.isArray(response) ? response : response.results
    },
  })
}

// Mutation Hooks

/**
 * Generate threats for a component based on its library type.
 */
export function useGenerateThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (componentId: number) =>
      api.post<GenerateThreatsResponse>(`/components/${componentId}/generate_threats/`),
    onSuccess: (_, componentId) => {
      queryClient.invalidateQueries({ queryKey: threatKeys.componentThreats(componentId) })
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Create a new component threat instance.
 * Can be from library (threatLibrary set) or custom (threatLibrary null).
 */
export function useCreateComponentThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      component: number
      threatLibrary?: number | null
      threatName?: string
      threatDescription?: string
      inherentSeverity: string
      status?: string
    }) => api.post<ComponentInstanceThreat>('/component-threats/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Create a new flow threat instance.
 * Can be from library (threatLibrary set) or custom (threatLibrary null).
 */
export function useCreateFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      dataFlow: number
      threatLibrary?: number | null
      threatName?: string
      threatDescription?: string
      inherentSeverity: string
      status?: string
    }) => api.post('/flow-threats/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Create a new component countermeasure instance.
 * Can be from library (countermeasureLibrary set) or custom (countermeasureLibrary null).
 */
export function useCreateComponentCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      instanceThreat: number
      countermeasureLibrary?: number | null
      countermeasureName?: string
      countermeasureDescription?: string
      controlType?: string
      status?: string
    }) => api.post<ComponentInstanceCountermeasure>('/component-countermeasures/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Create a new flow countermeasure instance.
 * Can be from library (countermeasureLibrary set) or custom (countermeasureLibrary null).
 */
export function useCreateFlowCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      flowThreat: number
      countermeasureLibrary?: number | null
      countermeasureName?: string
      countermeasureDescription?: string
      controlType?: string
      status?: string
    }) => api.post('/flow-countermeasures/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Apply a countermeasure to a threat instance.
 */
export function useApplyCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      countermeasureLibraryId,
      status,
    }: {
      threatId: number
      countermeasureLibraryId: number
      status?: string
    }) =>
      api.post<ApplyCountermeasureResponse>(`/component-threats/${threatId}/apply_countermeasure/`, {
        countermeasureLibraryId: countermeasureLibraryId,
        ...(status && { status }),
      }),
    onSuccess: (_, { threatId }) => {
      queryClient.invalidateQueries({ queryKey: threatKeys.suggestedCountermeasures(threatId) })
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Recalculate threat status based on countermeasures.
 */
export function useRecalculateThreatStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (threatId: number) =>
      api.post<RecalculateStatusResponse>(`/component-threats/${threatId}/recalculate_status/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Update a threat instance (e.g., status, severity).
 */
export function useUpdateThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      data,
    }: {
      threatId: number
      data: Partial<ComponentInstanceThreat>
    }) => api.patch<ComponentInstanceThreat>(`/component-threats/${threatId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
    },
  })
}

/**
 * Update a flow threat instance (e.g., status, severity).
 */
export function useUpdateFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      data,
    }: {
      threatId: number
      data: Record<string, unknown>
    }) => api.patch(`/flow-threats/${threatId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Dismiss a component threat.
 */
export function useDismissThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      reason,
    }: {
      threatId: number
      reason: string
    }) =>
      api.patch<ComponentInstanceThreat>(`/component-threats/${threatId}/`, {
        isDismissed: true,
        dismissalReason: reason,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Restore a dismissed component threat.
 */
export function useRestoreThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (threatId: number) =>
      api.patch<ComponentInstanceThreat>(`/component-threats/${threatId}/`, {
        isDismissed: false,
        dismissalReason: '',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Dismiss a flow threat.
 */
export function useDismissFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatId,
      reason,
    }: {
      threatId: number
      reason: string
    }) =>
      api.patch(`/flow-threats/${threatId}/`, {
        isDismissed: true,
        dismissalReason: reason,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Restore a dismissed flow threat.
 */
export function useRestoreFlowThreat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (threatId: number) =>
      api.patch(`/flow-threats/${threatId}/`, {
        isDismissed: false,
        dismissalReason: '',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Update a component countermeasure instance (e.g., status, evidenceUrl).
 */
export function useUpdateCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      countermeasureId,
      data,
    }: {
      countermeasureId: number
      data: Partial<ComponentInstanceCountermeasure>
    }) => {
      return api.patch<ComponentInstanceCountermeasure>(
        `/component-countermeasures/${countermeasureId}/`,
        data
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Update a flow countermeasure instance (e.g., status, evidenceUrl).
 */
export function useUpdateFlowCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      countermeasureId,
      data,
    }: {
      countermeasureId: number
      data: Partial<ComponentInstanceCountermeasure>
    }) => {
      return api.patch<ComponentInstanceCountermeasure>(
        `/flow-countermeasures/${countermeasureId}/`,
        data
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Delete a component countermeasure instance.
 */
export function useDeleteCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (countermeasureId: number) =>
      api.delete(`/component-countermeasures/${countermeasureId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Delete a flow countermeasure instance.
 */
export function useDeleteFlowCountermeasure() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (countermeasureId: number) =>
      api.delete(`/flow-countermeasures/${countermeasureId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Parse a countermeasure ID string to determine type and numeric ID.
 * Returns null if the ID format is not recognized.
 *
 * ID formats:
 * - "cm-123" -> component countermeasure with ID 123
 * - "fcm-123" -> flow countermeasure with ID 123
 * - "ctcm-..." -> local countermeasure (not backend)
 */
export function parseCountermeasureId(idString: string): {
  type: 'component' | 'flow' | 'local'
  id: number | null
} {
  if (idString.startsWith('cm-')) {
    const numId = parseInt(idString.slice(3), 10)
    return { type: 'component', id: isNaN(numId) ? null : numId }
  }
  if (idString.startsWith('fcm-')) {
    const numId = parseInt(idString.slice(4), 10)
    return { type: 'flow', id: isNaN(numId) ? null : numId }
  }
  if (idString.startsWith('ctcm-')) {
    return { type: 'local', id: null }
  }
  return { type: 'local', id: null }
}

// ============================================
// Threat Model Threats API
// ============================================

/**
 * Backend response for threat model threats endpoint.
 */
export interface EdgeDataflowMapEntry {
  dataflowId: number
  dfdId: string | null
  dfdName: string | null
  isAnalysisOnly?: boolean
  label?: string
  sourceComponentName?: string
  destComponentName?: string
}

export interface ThreatModelThreatsResponse {
  threatModelId: string
  threats: BackendThreat[]
  totalCount: number
  nodeComponentMap: Record<string, { componentId: number; dfdId: string; dfdName: string }>
  edgeDataflowMap: Record<string, EdgeDataflowMapEntry>
}

/**
 * Backend threat format.
 */
export interface BackendThreat {
  id: number
  type: 'component' | 'dataflow'
  componentId: number
  componentName: string | null
  nodeId: string | null
  edgeId?: string | null
  dataflowId?: number
  dataflowLabel?: string | null
  dfdId: string | null
  dfdName: string | null
  threatLibraryId: number
  threatName: string | null
  threatDescription: string | null
  taxonomyEntries?: TaxonomyEntry[]
  inherentSeverity: string
  residualSeverity: string
  status: 'exposed' | 'addressable' | 'mitigated'
  severityScoringMetadata: Record<string, unknown>
  isDismissed: boolean
  dismissalReason: string
  displayOrder?: number
  countermeasures: BackendCountermeasure[]
}

/**
 * Backend standard mapping format.
 */
export interface BackendStandardMapping {
  id: number
  frameworkName: string
  frameworkSlug: string
  sectionCode: string
  requirementDescription: string
  sufficiency: 'full' | 'partial'
}

/**
 * Backend countermeasure format.
 */
export interface BackendCountermeasure {
  id: number
  countermeasureLibraryId: number
  countermeasureName: string | null
  controlType: string | null
  status: BackendCountermeasureStatus
  priority: string
  evidenceUrl: string
  assignedOwnerEmail: string | null
  verifiedByEmail: string | null
  standardMappings: BackendStandardMapping[]
  displayOrder?: number
  isInherited?: boolean
  inheritedFromComponentName?: string | null
  inheritedFromZoneName?: string | null
}

/**
 * Transform backend threats to frontend ComponentThreat format.
 */
export function transformBackendThreatsToComponentThreats(
  backendThreats: BackendThreat[]
): ComponentThreat[] {
  const now = new Date().toISOString()

  return backendThreats.map((bt) => {
    // Use different prefixes for component vs dataflow threats
    const isDataflow = bt.type === 'dataflow'
    const componentThreatId = isDataflow ? `backend-flow-${bt.id}` : `backend-${bt.id}`

    // Use different countermeasure prefixes based on threat type
    const countermeasures: ComponentThreatCountermeasure[] = bt.countermeasures.map((cm) => ({
      id: isDataflow ? `fcm-${cm.id}` : `cm-${cm.id}`,
      countermeasureId: `lib-${cm.countermeasureLibraryId}`,
      componentThreatId,
      status: cm.status as CountermeasureStatus,
      priority: (cm.priority || 'none') as ComponentThreatCountermeasure['priority'],
      owner: cm.assignedOwnerEmail || undefined,
      notes: cm.evidenceUrl || undefined,
      createdAt: now,
      updatedAt: now,
      // Countermeasure metadata from backend (eliminates need for frontend registry lookup)
      countermeasureName: cm.countermeasureName || undefined,
      controlType: cm.controlType || undefined,
      standardMappings: cm.standardMappings || [],
      displayOrder: cm.displayOrder ?? 0,
      isInherited: cm.isInherited || false,
      inheritedFromComponentName: cm.inheritedFromComponentName || undefined,
      inheritedFromZoneName: cm.inheritedFromZoneName || undefined,
    }))

    return {
      id: componentThreatId,
      diagramId: bt.dfdId || '',
      sourceDiagramId: bt.dfdId || undefined,
      sourceDiagramTitle: bt.dfdName || undefined,
      // For dataflows, use the edge_id as componentId (for grouping in UI)
      componentId: isDataflow
        ? (bt.edgeId || `dataflow-${bt.dataflowId}`)
        : (bt.nodeId || `component-${bt.componentId}`),
      threatId: `lib-${bt.threatLibraryId}`,
      dismissed: bt.isDismissed,
      dismissalReason: bt.dismissalReason || undefined,
      countermeasures,
      createdAt: now,
      updatedAt: now,
      // Threat metadata from backend (eliminates need for frontend registry lookup)
      threatName: bt.threatName || undefined,
      threatDescription: bt.threatDescription || undefined,
      taxonomyEntries: bt.taxonomyEntries,
      // Severity scoring metadata
      inherentSeverity: bt.inherentSeverity,
      residualSeverity: bt.residualSeverity,
      severityScoringMetadata: bt.severityScoringMetadata,
      // Display order for drag-and-drop reordering
      displayOrder: bt.displayOrder ?? 0,
      // Backend IDs for API operations
      backendThreatId: bt.id,
      backendComponentId: bt.componentId,
      threatType: bt.type,
    }
  })
}

/**
 * Fetch all threats for a threat model (aggregated from all DFDs).
 */
export function useThreatModelThreats(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: ['threat-model-threats', threatModelId],
    queryFn: threatModelId
      ? async () => {
          const response = await api.get<ThreatModelThreatsResponse>(
            `/threat-models/${threatModelId}/threats/`
          )
          const transformed = transformBackendThreatsToComponentThreats(response.threats)
          return {
            ...response,
            componentThreats: transformed,
          }
        }
      : skipToken,
    staleTime: 30000, // Consider fresh for 30 seconds
  })
}

// ============================================
// Zone Protections API
// ============================================

export interface ZoneProtectionSuggestion {
  targetCountermeasureId: number
  targetComponentName: string
  targetZoneName: string
  sourceComponentName: string
  sourceZoneName: string
  countermeasureName: string
  controlType: string
}

interface ZoneProtectionsResponse {
  suggestions: ZoneProtectionSuggestion[]
  totalCount: number
}

interface ApplyZoneProtectionsResponse {
  updatedCount: number
}

/**
 * Fetch zone protection suggestions for a threat model.
 */
export function useZoneProtections(threatModelId: string | null | undefined, enabled = false) {
  return useQuery({
    queryKey: ['zone-protections', threatModelId],
    queryFn: threatModelId && enabled
      ? () => api.get<ZoneProtectionsResponse>(
          `/threat-models/${threatModelId}/zone_protections/`
        )
      : skipToken,
  })
}

/**
 * Parse a threat ID string to determine type and numeric ID.
 *
 * ID formats:
 * - "backend-123" -> component threat with ID 123
 * - "backend-flow-456" -> flow threat with ID 456
 */
export function parseThreatId(idString: string): {
  type: 'component' | 'flow' | 'unknown'
  id: number | null
} {
  if (idString.startsWith('backend-flow-')) {
    const numId = parseInt(idString.slice('backend-flow-'.length), 10)
    return { type: 'flow', id: isNaN(numId) ? null : numId }
  }
  if (idString.startsWith('backend-')) {
    const numId = parseInt(idString.slice('backend-'.length), 10)
    return { type: 'component', id: isNaN(numId) ? null : numId }
  }
  return { type: 'unknown', id: null }
}

/**
 * Reorder component threats.
 */
export function useReorderComponentThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/component-threats/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Reorder flow threats.
 */
export function useReorderFlowThreats() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/flow-threats/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Reorder component countermeasures.
 */
export function useReorderComponentCountermeasures() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/component-countermeasures/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Reorder flow countermeasures.
 */
export function useReorderFlowCountermeasures() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      api.post('/flow-countermeasures/reorder/', { orderedIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

/**
 * Apply selected zone protection suggestions.
 */
export function useApplyZoneProtections() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatModelId,
      items,
    }: {
      threatModelId: string
      items: { countermeasureId: number; sourceComponentName: string; sourceZoneName: string }[]
    }) =>
      api.post<ApplyZoneProtectionsResponse>(
        `/threat-models/${threatModelId}/apply_zone_protections/`,
        { items }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['zone-protections'] })
    },
  })
}
