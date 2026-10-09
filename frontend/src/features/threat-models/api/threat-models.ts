/**
 * API hooks for threat models and the rows nested under them: blueprints,
 * assumptions, business objectives, use cases, the review state and
 * approval, relationships, packs, and the CycloneDX TM-BOM import and export.
 *
 * Inventory systems (`/systems/`) are here too; a model has one optional
 * primary system (plan J1).
 */

import { useQuery, useMutation, useQueryClient, skipToken } from '@tanstack/react-query'
import type {
  ThreatModel,
  DashboardStats,
  System,
  CreateThreatModelInput,
  CreateSystemInput,
  UpdateSystemInput,
  Blueprint,
  CreateBlueprintInput,
  UpdateBlueprintInput,
  BlueprintDeletePreview,
  Assumption,
  CreateAssumptionInput,
  UpdateAssumptionInput,
  BusinessObjective,
  CreateBusinessObjectiveInput,
  UpdateBusinessObjectiveInput,
  ReviewState,
  UseCase,
  RelatedModel,
} from '@/features/threat-models/types/core'
import type { RelationType } from '@/types/domain'
import { api, getAccessToken } from '@/lib/api'

// Query keys
export const threatModelKeys = {
  all: ['threat-models'] as const,
  detail: (id: string) => [...threatModelKeys.all, id] as const,
  blueprints: (id: string) => ['threat-model-blueprints', id] as const,
  blueprintDeletePreview: (id: string, blueprintId: number) =>
    ['threat-model-blueprint-delete-preview', id, blueprintId] as const,
  assumptions: (id: string, blueprintId?: number) => ['threat-model-assumptions', id, blueprintId ?? 'all'] as const,
  businessObjectives: (id: string) => ['threat-model-business-objectives', id] as const,
  review: (id: string) => ['threat-model-review', id] as const,
  useCases: (id: string) => ['threat-model-use-cases', id] as const,
}

export const systemKeys = {
  all: ['systems'] as const,
  detail: (id: number) => [...systemKeys.all, id] as const,
}

// Query Hooks
export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.get<DashboardStats>('/dashboard/stats/'),
  })
}

export function useThreatModels(teamId?: number) {
  return useQuery({
    queryKey: ['threat-models', { teamId }],
    queryFn: async () => {
      const url = teamId
        ? `/threat-models/?owning_team=${teamId}`
        : '/threat-models/'
      const response = await api.get<{ results: ThreatModel[] } | ThreatModel[]>(url)
      // Handle both paginated and non-paginated responses
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useThreatModel(id: string) {
  return useQuery({
    queryKey: threatModelKeys.detail(id),
    queryFn: () => api.get<ThreatModel>(`/threat-models/${id}/`),
    enabled: !!id,
  })
}

// ============================================
// Inventory systems (plan J1)
// ============================================

export function useSystems() {
  return useQuery({
    queryKey: systemKeys.all,
    queryFn: async () => {
      const response = await api.get<{ results: System[] } | System[]>('/systems/')
      return Array.isArray(response) ? response : response.results
    },
  })
}

export function useSystem(systemId: number | null) {
  return useQuery({
    queryKey: systemKeys.detail(systemId ?? -1),
    queryFn: systemId !== null ? () => api.get<System>(`/systems/${systemId}/`) : skipToken,
  })
}

export function useCreateSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateSystemInput) =>
      api.post<System>('/systems/', input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.all })
    },
  })
}

export function useUpdateSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ systemId, data }: { systemId: number; data: UpdateSystemInput }) =>
      api.patch<System>(`/systems/${systemId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.all })
      queryClient.invalidateQueries({ queryKey: threatModelKeys.all })
    },
  })
}

/**
 * Delete an inventory system. A system that is some model's primary system
 * answers 409 with `{ error, models: [{ id, name }] }` (`SystemDeleteConflict`);
 * read it from `ApiError.data`.
 */
export function useDeleteSystem() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (systemId: number) => api.delete(`/systems/${systemId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.all })
      queryClient.invalidateQueries({ queryKey: threatModelKeys.all })
    },
  })
}

// Mutation Hooks
export function useCreateThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateThreatModelInput) =>
      api.post<ThreatModel>('/threat-models/', input),
    onSuccess: () => {
      // Invalidate related queries to refetch data
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
    },
  })
}

/**
 * Update a threat model. Changing `riskScoringMethod` on a model with risks
 * returns 400 with the methodology guard message; show it as a toast.
 */
export function useUpdateThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ThreatModel> }) =>
      api.patch<ThreatModel>(`/threat-models/${id}/`, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: threatModelKeys.review(id) })
    },
  })
}

export function useDeleteThreatModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => api.delete(`/threat-models/${id}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
    },
  })
}

export interface DeletePreviewDFD {
  id: string
  name: string
  nodeCount: number
}

export interface DeletePreviewResponse {
  threatModel: { id: string; name: string }
  dfdsToDelete: DeletePreviewDFD[]
  totalDfds: number
  componentsToDelete: number
  flowsToDelete: number
  threatsToDelete: number
  countermeasuresToDelete: number
}

export function useDeletePreview(id: string | null) {
  return useQuery({
    queryKey: ['threat-model-delete-preview', id],
    queryFn: () => api.get<DeletePreviewResponse>(`/threat-models/${id}/delete_preview/`),
    enabled: !!id,
  })
}

// DFD Delete Preview and Delete Hooks

export interface DFDDeletePreviewOrphanedComponent {
  id: number
  name: string
  libraryName: string | null
}

export interface DFDDeletePreviewResponse {
  dfd: {
    id: string
    name: string
    nodeCount: number
    componentCount: number
  }
  affectedThreatModels: Array<{ id: string; name: string }>
  orphanedComponents: DFDDeletePreviewOrphanedComponent[]
  orphanedComponentCount: number
}

export function useDFDDeletePreview(dfdId: string | null) {
  return useQuery({
    queryKey: ['dfd-delete-preview', dfdId],
    queryFn: () => api.get<DFDDeletePreviewResponse>(`/diagrams/${dfdId}/delete_preview/`),
    enabled: !!dfdId,
  })
}

export interface DeleteDFDOptions {
  dfdId: string
  deleteOrphanedComponents?: boolean
}

export function useDeleteDFD() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ dfdId, deleteOrphanedComponents = false }: DeleteDFDOptions) => {
      const params = deleteOrphanedComponents ? '?delete_orphaned_components=true' : ''
      return api.delete<{ status: string; orphanedComponentsDeleted: number }>(
        `/diagrams/${dfdId}/${params}`
      )
    },
    onSuccess: () => {
      // Invalidate all related queries
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
      // Invalidate components and threats (orphaned component deletion changes these)
      queryClient.invalidateQueries({ queryKey: ['components'] })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

// ============================================
// Related models (plan J15): relation_type worded from this model's side
// ============================================

/** 200 `{status, created, relationship}`; 400 `{error}` on a loop, a self link or an unknown type. */
export interface AddReferencedModelResponse {
  status: string
  created: boolean
  relationship: RelatedModel
}

export function useAddReferencedModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatModelId,
      targetModelId,
      relationType = 'related_to',
    }: {
      threatModelId: string
      targetModelId: number
      relationType?: RelationType
    }) =>
      api.post<AddReferencedModelResponse>(`/threat-models/${threatModelId}/add_referenced_model/`, {
        targetModelId,
        relationType,
      }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
    },
  })
}

export function useRemoveReferencedModel() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      threatModelId,
      targetModelId,
      relationType = 'related_to',
    }: {
      threatModelId: string
      targetModelId: number
      relationType?: RelationType
    }) =>
      api.post(`/threat-models/${threatModelId}/remove_referenced_model/`, { targetModelId, relationType }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
    },
  })
}

// ============================================
// Packs
// ============================================

export function useRemoveThreatModelPack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, packId }: { threatModelId: string; packId: number }) =>
      api.post<{ status: string; dependencyWarnings: Array<{ pack: string; message: string }> }>(
        `/threat-models/${threatModelId}/remove_pack/`,
        { packId }
      ),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
      queryClient.invalidateQueries({ queryKey: ['component-library'] })
      queryClient.invalidateQueries({ queryKey: ['component-library-raw'] })
      queryClient.invalidateQueries({ queryKey: ['dfd-templates'] })
      queryClient.invalidateQueries({ queryKey: ['threat-library'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasure-library'] })
    },
  })
}

export function useAddThreatModelPack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ threatModelId, packId }: { threatModelId: string; packId: number }) =>
      api.post(`/threat-models/${threatModelId}/add_pack/`, { packId }),
    onSuccess: (_, { threatModelId }) => {
      queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
      queryClient.invalidateQueries({ queryKey: ['component-library'] })
      queryClient.invalidateQueries({ queryKey: ['component-library-raw'] })
      queryClient.invalidateQueries({ queryKey: ['dfd-templates'] })
      queryClient.invalidateQueries({ queryKey: ['threat-library'] })
      queryClient.invalidateQueries({ queryKey: ['countermeasure-library'] })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}

// ============================================
// Blueprints: /threat-models/{id}/blueprints/ (plan 4.9, J2)
// ============================================

export function useBlueprints(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: threatModelKeys.blueprints(threatModelId ?? ''),
    queryFn: threatModelId
      ? () => api.get<Blueprint[]>(`/threat-models/${threatModelId}/blueprints/`)
      : skipToken,
  })
}

function invalidateBlueprints(queryClient: ReturnType<typeof useQueryClient>, threatModelId: string) {
  queryClient.invalidateQueries({ queryKey: threatModelKeys.blueprints(threatModelId) })
  queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
}

export function useCreateBlueprint(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateBlueprintInput) =>
      api.post<Blueprint>(`/threat-models/${threatModelId}/blueprints/`, data),
    onSuccess: () => invalidateBlueprints(queryClient, threatModelId),
  })
}

export function useUpdateBlueprint(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ blueprintId, data }: { blueprintId: number; data: UpdateBlueprintInput }) =>
      api.patch<Blueprint>(`/threat-models/${threatModelId}/blueprints/${blueprintId}/`, data),
    onSuccess: () => invalidateBlueprints(queryClient, threatModelId),
  })
}

/** What deleting a blueprint removes; `isLast` means the delete is refused. */
export function useBlueprintDeletePreview(threatModelId: string | null | undefined, blueprintId: number | null) {
  return useQuery({
    queryKey: threatModelKeys.blueprintDeletePreview(threatModelId ?? '', blueprintId ?? -1),
    queryFn:
      threatModelId && blueprintId !== null
        ? () =>
            api.get<BlueprintDeletePreview>(
              `/threat-models/${threatModelId}/blueprints/${blueprintId}/delete_preview/`
            )
        : skipToken,
  })
}

export function useDeleteBlueprint(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (blueprintId: number) =>
      api.delete(`/threat-models/${threatModelId}/blueprints/${blueprintId}/`),
    onSuccess: () => {
      invalidateBlueprints(queryClient, threatModelId)
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['diagrams'] })
      queryClient.invalidateQueries({ queryKey: ['components'] })
    },
  })
}

// ============================================
// Assumptions: /threat-models/{id}/assumptions/ (rows, plan step 9)
// ============================================

export function useAssumptions(threatModelId: string | null | undefined, blueprintId?: number) {
  return useQuery({
    queryKey: threatModelKeys.assumptions(threatModelId ?? '', blueprintId),
    queryFn: threatModelId
      ? async () => {
          const query = blueprintId !== undefined ? `?blueprint=${blueprintId}` : ''
          const response = await api.get<{ results: Assumption[] } | Assumption[]>(
            `/threat-models/${threatModelId}/assumptions/${query}`
          )
          return Array.isArray(response) ? response : response.results
        }
      : skipToken,
  })
}

function invalidateAssumptions(queryClient: ReturnType<typeof useQueryClient>, threatModelId: string) {
  queryClient.invalidateQueries({ queryKey: ['threat-model-assumptions', threatModelId] })
  queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
  queryClient.invalidateQueries({ queryKey: threatModelKeys.review(threatModelId) })
}

export function useCreateAssumption(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateAssumptionInput) =>
      api.post<Assumption>(`/threat-models/${threatModelId}/assumptions/`, data),
    onSuccess: () => invalidateAssumptions(queryClient, threatModelId),
  })
}

export function useUpdateAssumption(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ assumptionId, data }: { assumptionId: number; data: UpdateAssumptionInput }) =>
      api.patch<Assumption>(`/threat-models/${threatModelId}/assumptions/${assumptionId}/`, data),
    onSuccess: () => invalidateAssumptions(queryClient, threatModelId),
  })
}

export function useDeleteAssumption(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (assumptionId: number) =>
      api.delete(`/threat-models/${threatModelId}/assumptions/${assumptionId}/`),
    onSuccess: () => invalidateAssumptions(queryClient, threatModelId),
  })
}

// ============================================
// Business objectives: /threat-models/{id}/business-objectives/ (plan step 10)
// ============================================

export function useBusinessObjectives(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: threatModelKeys.businessObjectives(threatModelId ?? ''),
    queryFn: threatModelId
      ? () => api.get<BusinessObjective[]>(`/threat-models/${threatModelId}/business-objectives/`)
      : skipToken,
  })
}

function invalidateBusinessObjectives(queryClient: ReturnType<typeof useQueryClient>, threatModelId: string) {
  queryClient.invalidateQueries({ queryKey: threatModelKeys.businessObjectives(threatModelId) })
  queryClient.invalidateQueries({ queryKey: threatModelKeys.review(threatModelId) })
}

export function useCreateBusinessObjective(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateBusinessObjectiveInput) =>
      api.post<BusinessObjective>(`/threat-models/${threatModelId}/business-objectives/`, data),
    onSuccess: () => invalidateBusinessObjectives(queryClient, threatModelId),
  })
}

export function useUpdateBusinessObjective(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ objectiveId, data }: { objectiveId: number; data: UpdateBusinessObjectiveInput }) =>
      api.patch<BusinessObjective>(
        `/threat-models/${threatModelId}/business-objectives/${objectiveId}/`,
        data
      ),
    onSuccess: () => invalidateBusinessObjectives(queryClient, threatModelId),
  })
}

export function useDeleteBusinessObjective(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (objectiveId: number) =>
      api.delete(`/threat-models/${threatModelId}/business-objectives/${objectiveId}/`),
    onSuccess: () => {
      invalidateBusinessObjectives(queryClient, threatModelId)
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
      queryClient.invalidateQueries({ queryKey: ['risks'] })
    },
  })
}

// ============================================
// Use cases: /threat-models/{id}/use-cases/ (read and delete only, plan J14)
// ============================================

export function useUseCases(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: threatModelKeys.useCases(threatModelId ?? ''),
    queryFn: threatModelId
      ? async () => {
          const response = await api.get<{ results: UseCase[] } | UseCase[]>(
            `/threat-models/${threatModelId}/use-cases/`
          )
          return Array.isArray(response) ? response : response.results
        }
      : skipToken,
  })
}

export function useDeleteUseCase(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (useCaseId: number) =>
      api.delete(`/threat-models/${threatModelId}/use-cases/${useCaseId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: threatModelKeys.useCases(threatModelId) })
      queryClient.invalidateQueries({ queryKey: threatModelKeys.review(threatModelId) })
    },
  })
}

// ============================================
// Review and approval (plan 4.8, step 12)
// ============================================

export function useReviewState(threatModelId: string | null | undefined) {
  return useQuery({
    queryKey: threatModelKeys.review(threatModelId ?? ''),
    queryFn: threatModelId
      ? () => api.get<ReviewState>(`/threat-models/${threatModelId}/review/`)
      : skipToken,
  })
}

function invalidateReview(queryClient: ReturnType<typeof useQueryClient>, threatModelId: string) {
  queryClient.invalidateQueries({ queryKey: threatModelKeys.review(threatModelId) })
  queryClient.invalidateQueries({ queryKey: threatModelKeys.detail(threatModelId) })
  queryClient.invalidateQueries({ queryKey: ['threat-models'] })
}

export function useMarkReviewed(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => api.post<ReviewState>(`/threat-models/${threatModelId}/mark-reviewed/`),
    onSuccess: () => invalidateReview(queryClient, threatModelId),
  })
}

/** Security Team only (D4); others get 403. */
export function useApproveThreatModel(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => api.post<ReviewState>(`/threat-models/${threatModelId}/approve/`),
    onSuccess: () => invalidateReview(queryClient, threatModelId),
  })
}

/** Security Team only (D4); others get 403. */
export function useRevokeApproval(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => api.post<ReviewState>(`/threat-models/${threatModelId}/revoke-approval/`),
    onSuccess: () => invalidateReview(queryClient, threatModelId),
  })
}

// ============================================
// CycloneDX 2.0 TM-BOM Import/Export (the only format, L8)
// ============================================

/**
 * The counts the importer reports (`tmbom/importer/document.py` `count()`),
 * plus the warnings. Every count is optional: only sections the document had
 * are counted.
 */
export interface ImportSummary {
  threatModel?: number
  blueprints?: number
  zones?: number
  boundaries?: number
  components?: number
  systems?: number
  dataAssets?: number
  flows?: number
  diagrams?: number
  diagramsGenerated?: number
  outOfScopeItems?: number
  useCases?: number
  assumptions?: number
  businessObjectives?: number
  threatPersonas?: number
  threats?: number
  controls?: number
  risks?: number
  riskResponses?: number
  relationships?: number
  warnings: string[]
}

export interface ImportCycloneDxResponse {
  threatModel: { id: string; name: string }
  summary: ImportSummary
}

export function useImportCycloneDx() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (file: File) =>
      api.uploadFile<ImportCycloneDxResponse>(
        '/threat-models/import/cyclonedx/',
        file,
        undefined,
        'file'
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threat-models'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard', 'stats'] })
    },
  })
}

/**
 * Download the model as a CycloneDX TM-BOM. Returns what the export had to
 * leave out (stale refs in kept content), from the `X-Export-Warnings` header.
 */
export async function exportCycloneDx(threatModelId: string): Promise<string[]> {
  const token = getAccessToken()
  const response = await fetch(`/api/threat-models/${threatModelId}/export/cyclonedx/`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })

  if (!response.ok) {
    throw new Error(`Export failed: ${response.status}`)
  }

  const blob = await response.blob()
  const contentDisposition = response.headers.get('Content-Disposition')
  const filenameMatch = contentDisposition?.match(/filename="(.+)"/)
  const filename = filenameMatch?.[1] || 'threat-model-cyclonedx.cdx.json'

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)

  return parseExportWarnings(response.headers.get('X-Export-Warnings'))
}

/** The export warnings header as a list; anything unreadable counts as none. */
export function parseExportWarnings(header: string | null): string[] {
  if (!header) return []
  try {
    const parsed: unknown = JSON.parse(header)
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

/** The BOM-Link of a model: `urn:cdx:<serial number>/<version>` (plan J9). */
export function bomLink(threatModel: Pick<ThreatModel, 'serialNumber' | 'version'>): string | null {
  if (!threatModel.serialNumber) return null
  return `urn:cdx:${threatModel.serialNumber}/${threatModel.version ?? 1}`
}
