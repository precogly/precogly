/**
 * React Query hooks for AI-powered DFD generation from architecture diagrams.
 *
 * Two-step flow:
 *  1. `analyze-image` (POST, multipart): send architecture diagram image + context,
 *     receive extracted components, flows, zones, and clarifying questions.
 *  2. `generate-dfd` (POST, JSON): send analysis + user answers, receive canvas_data
 *     (nodes + edges) ready for insertion via handleInsertTemplate.
 *
 * Plus an availability check that mirrors the suggest-threats pattern.
 *
 * Query params stay snake_case (not converted by djangorestframework-camel-case).
 * Body fields are camelCase (converted automatically).
 */

import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'

// ---------- Types ----------

/** backend/apps/diagrams/ai/analyze.py normalize_analysis: unknown values are dropped. */
export interface AnalysisComponent {
  name: string
  type: 'process' | 'datastore' | 'humanActor' | 'systemActor'
  description: string
  technology: string
  zone?: string
  kind?: string
  dataSensitivity: string
}

export interface AnalysisFlow {
  from: string
  to: string
  description: string
  /** A flow type; absent means data. */
  type?: string
  protocol: string
  encrypted: boolean
  /** Authentication methods; empty when the diagram does not say. */
  authentication: string[]
}

export interface AnalysisZone {
  name: string
  /** A zone type; absent means trust. */
  type?: string
  trustLevel?: number
}

export interface AnalysisResult {
  components: AnalysisComponent[]
  flows: AnalysisFlow[]
  zones: AnalysisZone[]
  systemScope: { name: string; description: string }
  questions: string[]
}

export interface QuestionAnswer {
  question: string
  answer: string
}

export interface GenerateDFDResponse {
  nodes: Record<string, unknown>[]
  edges: Record<string, unknown>[]
}

export interface DfdAiAvailability {
  available: boolean
  reason: string | null
}

// ---------- Query keys ----------

export const dfdGenerateKeys = {
  availability: (threatModelId: string) =>
    ['dfd-ai-availability', threatModelId] as const,
}

// ---------- Hooks ----------

/**
 * Whether AI-powered DFD generation is available for this threat model's org.
 * Cached 60s; availability changes rarely.
 */
export function useDfdAiAvailability(threatModelId: string | undefined) {
  return useQuery({
    queryKey: dfdGenerateKeys.availability(threatModelId ?? ''),
    queryFn: () =>
      api.get<DfdAiAvailability>(
        `/diagrams/ai-availability/?threat_model_id=${threatModelId}`
      ),
    enabled: !!threatModelId,
    staleTime: 60_000,
  })
}

/**
 * Analyze an architecture diagram image. Returns extracted components,
 * data flows, trust zones, and clarifying questions.
 */
export function useAnalyzeImage() {
  return useMutation({
    mutationFn: ({
      image,
      appName,
      appDescription,
      threatModelId,
    }: {
      image: File
      appName: string
      appDescription: string
      threatModelId: string
    }) =>
      api.uploadFile<AnalysisResult>('/diagrams/analyze-image/', image, {
        app_name: appName,
        app_description: appDescription,
        threat_model_id: threatModelId,
      }),
  })
}

/**
 * Generate DFD canvas data from a prior analysis and the user's answers to
 * clarifying questions.
 */
export function useGenerateDfd() {
  return useMutation({
    mutationFn: ({
      threatModelId,
      analysis,
      answers,
    }: {
      threatModelId: string
      analysis: AnalysisResult
      answers: QuestionAnswer[]
    }) =>
      api.post<GenerateDFDResponse>('/diagrams/generate-dfd/', {
        threatModelId,
        analysis,
        answers,
      }),
  })
}
