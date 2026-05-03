import { createContext, useContext, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { deriveThreatStatus, worseSeverity } from '../types/threat-analysis'
import type { ThreatModelThreatsResponse } from '@/features/threat-models/api/threats'
import { transformBackendThreatsToComponentThreats } from '@/features/threat-models/api/threats'

export interface NodeThreatSummary {
  total: number
  exposed: number
  addressable: number
  mitigated: number
  /** Highest inherent severity across active threats on this node (for tooltips). */
  worstInherent?: string
  /** Highest residual severity across active threats on this node (for tooltips). */
  worstResidual?: string
}

type ThreatSummaryMap = Map<string, NodeThreatSummary>

interface ThreatSummaryContextValue {
  summaryMap: ThreatSummaryMap
  threatModelId: string | undefined
}

const ThreatSummaryContext = createContext<ThreatSummaryContextValue>({
  summaryMap: new Map(),
  threatModelId: undefined,
})

export function ThreatSummaryProvider({
  threatModelId,
  children,
}: {
  threatModelId: string | undefined
  children: React.ReactNode
}) {
  const { data } = useQuery({
    queryKey: ['threat-model-threats', threatModelId],
    queryFn: threatModelId
      ? async () => {
          const response = await api.get<ThreatModelThreatsResponse>(
            `/threat-models/${threatModelId}/threats/`
          )
          return {
            ...response,
            componentThreats: transformBackendThreatsToComponentThreats(response.threats),
          }
        }
      : undefined,
    enabled: !!threatModelId,
    staleTime: 0,
    refetchOnWindowFocus: true,
  })

  const summaryMap = useMemo<ThreatSummaryMap>(() => {
    const map = new Map<string, NodeThreatSummary>()
    if (!data?.componentThreats) return map

    for (const threat of data.componentThreats) {
      if (threat.dismissed) continue
      const nodeId = threat.componentId
      if (!nodeId) continue

      const existing = map.get(nodeId) ?? {
        total: 0,
        exposed: 0,
        addressable: 0,
        mitigated: 0,
        worstInherent: undefined as string | undefined,
        worstResidual: undefined as string | undefined,
      }
      const status = deriveThreatStatus(threat.countermeasures)
      map.set(nodeId, {
        total: existing.total + 1,
        exposed: existing.exposed + (status === 'exposed' ? 1 : 0),
        addressable: existing.addressable + (status === 'addressable' ? 1 : 0),
        mitigated: existing.mitigated + (status === 'mitigated' ? 1 : 0),
        worstInherent: worseSeverity(existing.worstInherent, threat.inherentSeverity),
        worstResidual: worseSeverity(existing.worstResidual, threat.residualSeverity),
      })
    }
    return map
  }, [data?.componentThreats])

  return (
    <ThreatSummaryContext.Provider value={{ summaryMap, threatModelId }}>
      {children}
    </ThreatSummaryContext.Provider>
  )
}

export function useThreatSummary(nodeId: string): NodeThreatSummary | null {
  const { summaryMap } = useContext(ThreatSummaryContext)
  return summaryMap.get(nodeId) ?? null
}
