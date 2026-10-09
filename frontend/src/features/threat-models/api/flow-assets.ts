/**
 * API hooks for flow assets: the data assets carried by a flow
 * (`/flow-assets/?flow=`).
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'

/** backend/apps/systems/serializers.py FlowAssetSerializer */
export interface FlowAsset {
  id: number
  flow: number
  /** "source → destination" */
  flowName: string
  dataAsset: number
  dataAssetName: string
  protectionMethod: 'encrypted' | 'masked' | 'tokenized' | 'hashed' | 'none'
  encryptionType: string
  format: string
  sensitivityOverride: string
  createdAt: string
  updatedAt: string
}

export const flowAssetKeys = {
  all: ['flow-assets'] as const,
  forFlow: (flowId: number) => [...flowAssetKeys.all, flowId] as const,
}

export function useFlowAssets(flowId: number | undefined) {
  return useQuery({
    queryKey: flowAssetKeys.forFlow(flowId ?? -1),
    queryFn: async () => {
      const response = await api.get<{ results: FlowAsset[] } | FlowAsset[]>(`/flow-assets/?flow=${flowId}`)
      return Array.isArray(response) ? response : response.results
    },
    enabled: !!flowId,
  })
}

export function useCreateFlowAsset() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: Partial<FlowAsset> & { flow: number; dataAsset: number }) =>
      api.post<FlowAsset>('/flow-assets/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: flowAssetKeys.all })
    },
  })
}

export function useUpdateFlowAsset() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<FlowAsset> }) =>
      api.patch<FlowAsset>(`/flow-assets/${id}/`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: flowAssetKeys.all })
    },
  })
}

export function useDeleteFlowAsset() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: number) => api.delete(`/flow-assets/${id}/`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: flowAssetKeys.all })
    },
  })
}
