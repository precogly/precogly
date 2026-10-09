/**
 * API hooks for flows (`/flows/`). A flow has a type (plan 4.6); protocol,
 * port and encryption apply to data-like types only.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AuthenticationType, AuthorizationType, FlowType } from '@/types/domain'

/** backend/apps/systems/serializers.py FlowSerializer */
export interface Flow {
  id: number
  blueprint: number
  sourceComponent: number
  sourceComponentName: string
  destComponent: number
  destComponentName: string
  label: string
  description: string
  edgeId: string | null
  flowType: FlowType
  protocol: string
  port: number | null
  encrypted: boolean
  authentication: AuthenticationType[]
  authorization: AuthorizationType[]
  /** Derived: the authentication list is not empty and has no `none` (I5). */
  requiresAuthentication: boolean
  /** Derived by sync: true when a boundary has the two ends on opposite sides (H19). */
  crossesBoundary: boolean
  hasSensitiveData: boolean
  dataClassification: string[]
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export type UpdateFlowInput = Partial<
  Pick<
    Flow,
    | 'label'
    | 'description'
    | 'flowType'
    | 'protocol'
    | 'port'
    | 'encrypted'
    | 'authentication'
    | 'authorization'
    | 'hasSensitiveData'
    | 'dataClassification'
  >
>

export const flowKeys = {
  all: ['flows'] as const,
  list: (scope: { blueprint?: number; threatModel?: string; flowType?: FlowType }) =>
    [...flowKeys.all, scope] as const,
  detail: (flowId: number) => [...flowKeys.all, 'detail', flowId] as const,
}

export function useFlows(scope: { blueprint?: number; threatModel?: string | null; flowType?: FlowType }) {
  const blueprint = scope.blueprint
  const threatModel = scope.threatModel ?? undefined
  const flowType = scope.flowType
  return useQuery({
    queryKey: flowKeys.list({ blueprint, threatModel, flowType }),
    queryFn: async () => {
      const params = new URLSearchParams()
      if (blueprint !== undefined) params.set('blueprint', String(blueprint))
      else if (threatModel) params.set('threat_model', threatModel)
      if (flowType) params.set('flow_type', flowType)
      const query = params.toString()
      const response = await api.get<{ results: Flow[] } | Flow[]>(query ? `/flows/?${query}` : '/flows/')
      return Array.isArray(response) ? response : response.results
    },
    enabled: blueprint !== undefined || !!threatModel,
  })
}

export function useUpdateFlow() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ flowId, data }: { flowId: number; data: UpdateFlowInput }) =>
      api.patch<Flow>(`/flows/${flowId}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: flowKeys.all })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats'] })
    },
  })
}
