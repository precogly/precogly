/**
 * API hooks for risks, risk responses and countermeasure comments.
 *
 * Risks live under `/threat-models/{id}/risks/` and carry three read-only
 * ratings (`inherent`, `residual`, `target`); writes take `ratingInputs`.
 * Responses live under `/threat-models/{id}/risks/{riskId}/responses/`.
 */

import {
  useQuery,
  useMutation,
  useQueryClient,
  skipToken,
  keepPreviousData,
} from '@tanstack/react-query'
import { api, getPage } from '@/lib/api'
import type {
  Risk,
  RiskResponse,
  RiskStatus,
  ScoringMethod,
  CreateRiskInput,
  UpdateRiskInput,
  CreateRiskResponseInput,
  UpdateRiskResponseInput,
  AddRemoveThreatsInput,
  BulkUpdateRisksInput,
  CountermeasureComment,
} from '@/types/risk'

// Query keys
export const riskKeys = {
  all: ['risks'] as const,
  // Every page's key extends `list`, so the mutations below can keep
  // invalidating `list` alone and still reach whichever pages are cached.
  list: (threatModelId: string) => [...riskKeys.all, 'list', threatModelId] as const,
  page: (threatModelId: string, page: number, pageSize: number, filters: RiskListFilters) =>
    [...riskKeys.list(threatModelId), { page, pageSize, ...filters }] as const,
  detail: (threatModelId: string, riskId: number) =>
    [...riskKeys.all, 'detail', threatModelId, riskId] as const,
  responses: (threatModelId: string, riskId: number) =>
    [...riskKeys.all, 'responses', threatModelId, riskId] as const,
  scoringMethods: ['scoring-methods'] as const,
}

/**
 * Page sizes the register offers.
 *
 * The largest must not exceed `ClientSizedPagination.max_page_size` (200). The
 * server clamps a larger request rather than rejecting it, so the page controls
 * would compute a page count from a size they never got.
 */
export const RISK_PAGE_SIZES = [20, 50, 100, 200] as const
export const DEFAULT_RISK_PAGE_SIZE = RISK_PAGE_SIZES[0]

export interface RiskListFilters {
  status?: RiskStatus
  /** `inherent__level` filter. */
  inherentLevel?: string
  /** `residual__level` filter. */
  residualLevel?: string
  search?: string
  /** One of inherent_rank, residual_rank, inherent__score, residual__score, created_at, name (prefix `-` to reverse). */
  ordering?: string
}

function riskListEndpoint(threatModelId: string, filters: RiskListFilters): string {
  const params = new URLSearchParams()
  if (filters.status) params.set('status', filters.status)
  if (filters.inherentLevel) params.set('inherent__level', filters.inherentLevel)
  if (filters.residualLevel) params.set('residual__level', filters.residualLevel)
  if (filters.search) params.set('search', filters.search)
  if (filters.ordering) params.set('ordering', filters.ordering)
  const query = params.toString()
  const base = `/threat-models/${threatModelId}/risks/`
  return query ? `${base}?${query}` : base
}

/**
 * Fetch one page of a threat model's risks.
 *
 * Returns the whole `Page`. Returning `results` alone is what made the header
 * report 20 risks for a register of 24: the total lives in `count`.
 */
export function useRisks(
  threatModelId: string | null | undefined,
  {
    page = 1,
    pageSize = DEFAULT_RISK_PAGE_SIZE,
    ...filters
  }: { page?: number; pageSize?: number } & RiskListFilters = {}
) {
  return useQuery({
    queryKey: riskKeys.page(threatModelId ?? '', page, pageSize, filters),
    queryFn: threatModelId
      ? () => getPage<Risk>(riskListEndpoint(threatModelId, filters), { page, pageSize })
      : skipToken,
    // Hold the previous page on screen while the next one loads. Without this
    // every page step unmounts the table and shows the tab-wide spinner.
    placeholderData: keepPreviousData,
  })
}

/**
 * Fetch a single risk detail.
 */
export function useRisk(threatModelId: string | null | undefined, riskId: number | null) {
  return useQuery({
    queryKey: riskKeys.detail(threatModelId ?? '', riskId ?? -1),
    queryFn:
      threatModelId && riskId
        ? () => api.get<Risk>(`/threat-models/${threatModelId}/risks/${riskId}/`)
        : skipToken,
  })
}

/**
 * Fetch available scoring methods (`GET /scoring-methods/`).
 */
export function useScoringMethods() {
  return useQuery({
    queryKey: riskKeys.scoringMethods,
    queryFn: () => api.get<ScoringMethod[]>('/scoring-methods/'),
    staleTime: Infinity,
  })
}

/**
 * Create a new risk. `ratingInputs` is required.
 */
export function useCreateRisk(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateRiskInput) =>
      api.post<Risk>(`/threat-models/${threatModelId}/risks/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
    },
  })
}

/**
 * Update an existing risk.
 */
export function useUpdateRisk(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ riskId, data }: { riskId: number; data: UpdateRiskInput }) =>
      api.patch<Risk>(`/threat-models/${threatModelId}/risks/${riskId}/`, data),
    onSuccess: (_, { riskId }) => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
      queryClient.invalidateQueries({ queryKey: riskKeys.detail(threatModelId, riskId) })
    },
  })
}

/**
 * Delete a risk.
 */
export function useDeleteRisk(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (riskId: number) =>
      api.delete(`/threat-models/${threatModelId}/risks/${riskId}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
    },
  })
}

/**
 * Recalculate a risk's residual rating.
 */
export function useRecalculateRisk(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (riskId: number) =>
      api.post<Risk>(`/threat-models/${threatModelId}/risks/${riskId}/recalculate/`),
    onSuccess: (_, riskId) => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
      queryClient.invalidateQueries({ queryKey: riskKeys.detail(threatModelId, riskId) })
    },
  })
}

/**
 * Add threats to a risk (`add-threats`, body `{ threatIds }`).
 */
export function useAddRiskThreats(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ riskId, data }: { riskId: number; data: AddRemoveThreatsInput }) =>
      api.post<Risk>(`/threat-models/${threatModelId}/risks/${riskId}/add-threats/`, data),
    onSuccess: (_, { riskId }) => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
      queryClient.invalidateQueries({ queryKey: riskKeys.detail(threatModelId, riskId) })
    },
  })
}

/**
 * Remove threats from a risk (`remove-threats`, body `{ threatIds }`).
 */
export function useRemoveRiskThreats(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ riskId, data }: { riskId: number; data: AddRemoveThreatsInput }) =>
      api.post<Risk>(`/threat-models/${threatModelId}/risks/${riskId}/remove-threats/`, data),
    onSuccess: (_, { riskId }) => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
      queryClient.invalidateQueries({ queryKey: riskKeys.detail(threatModelId, riskId) })
    },
  })
}

/**
 * Bulk update status or owner on multiple risks.
 */
export function useBulkUpdateRisks(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: BulkUpdateRisksInput) =>
      api.post<{ updated: number }>(`/threat-models/${threatModelId}/risks/bulk-update/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
    },
  })
}

// ============================================
// Risk responses
// ============================================

function invalidateRisk(queryClient: ReturnType<typeof useQueryClient>, threatModelId: string, riskId: number) {
  queryClient.invalidateQueries({ queryKey: riskKeys.responses(threatModelId, riskId) })
  queryClient.invalidateQueries({ queryKey: riskKeys.detail(threatModelId, riskId) })
  queryClient.invalidateQueries({ queryKey: riskKeys.list(threatModelId) })
}

export function useRiskResponses(threatModelId: string | null | undefined, riskId: number | null) {
  return useQuery({
    queryKey: riskKeys.responses(threatModelId ?? '', riskId ?? -1),
    queryFn:
      threatModelId && riskId
        ? async () => {
            const response = await api.get<{ results: RiskResponse[] } | RiskResponse[]>(
              `/threat-models/${threatModelId}/risks/${riskId}/responses/`
            )
            return Array.isArray(response) ? response : response.results
          }
        : skipToken,
  })
}

export function useCreateRiskResponse(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ riskId, data }: { riskId: number; data: CreateRiskResponseInput }) =>
      api.post<RiskResponse>(`/threat-models/${threatModelId}/risks/${riskId}/responses/`, data),
    onSuccess: (_, { riskId }) => invalidateRisk(queryClient, threatModelId, riskId),
  })
}

export function useUpdateRiskResponse(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      riskId,
      responseId,
      data,
    }: {
      riskId: number
      responseId: number
      data: UpdateRiskResponseInput
    }) =>
      api.patch<RiskResponse>(
        `/threat-models/${threatModelId}/risks/${riskId}/responses/${responseId}/`,
        data
      ),
    onSuccess: (_, { riskId }) => invalidateRisk(queryClient, threatModelId, riskId),
  })
}

export function useDeleteRiskResponse(threatModelId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ riskId, responseId }: { riskId: number; responseId: number }) =>
      api.delete(`/threat-models/${threatModelId}/risks/${riskId}/responses/${responseId}/`),
    onSuccess: (_, { riskId }) => invalidateRisk(queryClient, threatModelId, riskId),
  })
}

// ============================================
// Countermeasure comments (one countermeasure table, one key)
// ============================================

export const countermeasureCommentKeys = {
  all: ['countermeasure-comments'] as const,
  forCountermeasure: (countermeasureId: number) =>
    [...countermeasureCommentKeys.all, countermeasureId] as const,
}

/**
 * Fetch comments for a countermeasure.
 */
export function useCountermeasureComments(countermeasureId: number | null) {
  return useQuery({
    queryKey: countermeasureCommentKeys.forCountermeasure(countermeasureId ?? -1),
    queryFn:
      countermeasureId !== null
        ? async () => {
            const res = await api.get<{ results: CountermeasureComment[] } | CountermeasureComment[]>(
              `/countermeasure-comments/?countermeasure=${countermeasureId}`
            )
            return Array.isArray(res) ? res : res.results
          }
        : skipToken,
  })
}

/**
 * Add a comment to a countermeasure.
 */
export function useAddCountermeasureComment() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: { countermeasure: number; body: string; changeSummary?: string }) =>
      api.post<CountermeasureComment>('/countermeasure-comments/', data),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({
        queryKey: countermeasureCommentKeys.forCountermeasure(vars.countermeasure),
      })
    },
  })
}
