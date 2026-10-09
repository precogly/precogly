/**
 * React Query hooks for the AI "suggest threats" feature.
 *
 * Two endpoints on the one threat viewset back the owl in the component view:
 *  - `ai_availability` (cheap, GET): does this target's org have AI enabled?
 *    Drives whether the owl is active or routes to provider setup, decided
 *    *before* the user clicks so we never fire a request that can only 400.
 *  - `suggest` (the real work, POST): grounded, ranked threat candidates for a
 *    target. Component targets only in this version; other target types
 *    answer an empty list. It persists nothing: the user reviews and accepts
 *    each one through the normal create path, so this is a mutation we
 *    trigger on demand rather than a query that auto-refetches an LLM call.
 *
 * Request/response casing crosses the snake_case <-> camelCase boundary
 * automatically (djangorestframework-camel-case), so bodies are camelCase here.
 * Query params are the exception: they are not converted, hence the literal
 * `target_id` below, matching the rest of the threats API.
 */

import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { RatingLevel } from '@/types/risk'

export type SuggestTargetType = 'component' | 'flow' | 'zone' | 'boundary'

export interface ThreatSuggestion {
  threatLibrary: number
  threatName: string
  threatDescription: string
  /** The pack's default level for this component type. */
  defaultLevel: RatingLevel
  /** The model's pick when it is a real level, else the pack's default. */
  suggestedSeverity: RatingLevel
  rationale: string
  taxonomy: string[]
  source: { qualifiedSlug: string; packName: string | null }
}

export interface SuggestThreatsResponse {
  targetType: SuggestTargetType
  targetId: number
  suggestions: ThreatSuggestion[]
}

export interface AiAvailability {
  available: boolean
  reason: string | null
}

export const aiSuggestKeys = {
  availability: (targetId: number) => ['ai-availability', targetId] as const,
}

/**
 * Whether AI suggestions are available for the component's organization.
 * Cached per component; availability changes rarely, so it stays fresh a while.
 */
export function useAiAvailability(componentId: number | null) {
  return useQuery({
    queryKey: aiSuggestKeys.availability(componentId ?? -1),
    queryFn: () =>
      api.get<AiAvailability>(`/threats/ai_availability/?target_id=${componentId}`),
    enabled: componentId !== null,
    staleTime: 60_000,
  })
}

/**
 * Request ranked, grounded threat suggestions for a target. Triggered when
 * the owl popover opens; re-run via "Regenerate".
 */
export function useSuggestThreats() {
  return useMutation({
    mutationFn: ({ targetType = 'component', targetId }: { targetType?: SuggestTargetType; targetId: number }) =>
      api.post<SuggestThreatsResponse>('/threats/suggest/', { targetType, targetId }),
  })
}
