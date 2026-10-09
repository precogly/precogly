import { useState, useEffect, useCallback, useMemo } from 'react'
import type { Diagram } from '@/types'
import type {
  CompletionStatus,
  AnalysisThreat,
  AnalysisCountermeasure,
  CountermeasureStatus,
  ProgressChecklistItem,
} from '@/features/dfd-editor/types/threat-analysis'
import { deriveThreatStatus, targetCanvasId } from '@/features/dfd-editor/types/threat-analysis'
import {
  useThreatModelThreats,
  useUpdateCountermeasure,
  useUpdateTriageStatus,
  useReorderThreats,
  useReorderCountermeasures,
} from '@/features/threat-models/api/threats'
import { parseCountermeasureId, threatIdFromUiId } from '@/features/threat-models/lib/threat-ids'
import { isActiveThreat, type TriageStatus } from '@/types/triage'
import { useThreatModel } from '@/features/threat-models/api/threat-models'
import { ApiError } from '@/lib/api'
import { toast } from 'sonner'
import type { AnalysisSelection } from '@/features/dfd-editor/components/threat-analysis/analysis-selection'

/** The message of a failed write, for the toast: the 403 on platform status names the role. */
function writeErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'Only the Security Team can set or remove platform status.'
    if (error.data && typeof error.data === 'object') {
      const detail = (error.data as { detail?: unknown }).detail
      if (typeof detail === 'string') return detail
      const firstValue = Object.values(error.data as Record<string, unknown>)[0]
      if (typeof firstValue === 'string') return firstValue
      if (Array.isArray(firstValue) && typeof firstValue[0] === 'string') return firstValue[0]
    }
  }
  return fallback
}

interface WorkspaceThreatAnalysisState {
  threatModelId: string
  /** Every scenario of the model in the screen's shape (one entry per scenario). */
  threats: AnalysisThreat[]
}

function getDefaultState(threatModelId: string | undefined): WorkspaceThreatAnalysisState {
  return {
    threatModelId: threatModelId || '',
    threats: [],
  }
}

// NOTE: Local threat generation has been removed from this hook.
// The backend is now the single source of truth for threats.

export function useWorkspaceThreatAnalysis(
  threatModelId: string | undefined,
  diagrams: Diagram[],
  analysisComponents: { id: number; category: string }[] = []
) {
  const [state, setState] = useState<WorkspaceThreatAnalysisState>(() =>
    getDefaultState(threatModelId)
  )

  // Fetch threat model for workspace_data
  const { data: threatModel, isLoading: isLoadingThreatModel } = useThreatModel(threatModelId!)

  // Fetch threats from backend API
  const { data: backendThreats, isLoading: isLoadingThreats } = useThreatModelThreats(threatModelId)

  // Backend API mutations
  const updateCountermeasureMutation = useUpdateCountermeasure()
  const updateTriageStatusMutation = useUpdateTriageStatus()
  const reorderThreatsMutation = useReorderThreats()
  const reorderCountermeasuresMutation = useReorderCountermeasures()

  // Use backend threats directly - no local threat generation
  useEffect(() => {
    if (backendThreats?.analysisThreats) {
      setState((prev) => ({
        ...prev,
        threats: backendThreats.analysisThreats,
      }))
    }
  }, [backendThreats])

  // Drop threats whose every target is gone from the current diagrams. A
  // whole-system threat, an analysis-only target and a target off any canvas
  // (zones and boundaries on no diagram) are always kept.
  useEffect(() => {
    if (!diagrams || diagrams.length === 0) return
    if (isLoadingThreats) return

    setState((prev) => {
      const validCanvasIds = new Set<string>()
      const currentDiagramIds = new Set<string>()
      diagrams.forEach((d) => {
        currentDiagramIds.add(String(d.id))
        const canvasData = d.canvasData
        if (canvasData) {
          canvasData.nodes?.forEach((node) => validCanvasIds.add(String(node.id)))
          canvasData.edges?.forEach((edge) => validCanvasIds.add(String(edge.id)))
        }
      })

      const filteredThreats = prev.threats.filter((threat) => {
        if (threat.wholeSystem || threat.targets.length === 0) return true
        return threat.targets.some((target) => {
          const canvasId = targetCanvasId(target)
          if (!canvasId) return true
          if (canvasId.startsWith('analysis-')) return true
          if (!target.dfdId) return true
          return currentDiagramIds.has(target.dfdId) && validCanvasIds.has(canvasId)
        })
      })

      if (filteredThreats.length !== prev.threats.length) {
        return { ...prev, threats: filteredThreats }
      }
      return prev
    })
  }, [diagrams, isLoadingThreats])

  // Update countermeasure status
  const updateCountermeasureStatus = useCallback(
    (
      _componentThreatId: string,
      countermeasureInstanceId: string,
      status: CountermeasureStatus,
      notes?: string
    ) => {
      // Use the instance ID directly for the API call (always unique)
      const parsed = parseCountermeasureId(countermeasureInstanceId)

      if (parsed.type === 'backend' && parsed.id !== null) {
        updateCountermeasureMutation.mutate(
          {
            countermeasureId: parsed.id,
            data: {
              status,
              ...(notes !== undefined && { evidenceUrl: notes }),
            },
          },
          {
            // The backend refuses platform status without the Security Team
            // role (403); the toast says so and the refetch undoes the
            // optimistic change below.
            onError: (error) => toast.error(writeErrorMessage(error, 'Could not change the status')),
          }
        )
      }

      // Update local state immediately for responsiveness
      // For shared countermeasures, update across ALL threats that share this CM
      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          const hasCm = ct.countermeasures.some((cm) => cm.id === countermeasureInstanceId)
          if (!hasCm) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                status,
                ...(notes !== undefined && { notes }),
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [updateCountermeasureMutation]
  )

  // Assign owner to countermeasure
  const assignOwner = useCallback(
    (
      componentThreatId: string,
      countermeasureInstanceId: string,
      assignee: { type: 'member'; userId: number; email: string; name: string | null },
      newStatus?: CountermeasureStatus
    ) => {
      const threat = state.threats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        const data: { assignedOwner: number; status?: CountermeasureStatus } = { assignedOwner: assignee.userId }
        if (newStatus) {
          data.status = newStatus
        }

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data,
          })
        }
      }

      const finalStatus = newStatus || (countermeasure?.status === 'gap' ? 'planned' : countermeasure?.status)
      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                owner: assignee.email,
                status: finalStatus || cm.status,
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [state.threats, updateCountermeasureMutation]
  )

  // Update countermeasure priority
  const updateCountermeasurePriority = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, priority: AnalysisCountermeasure['priority']) => {
      const threat = state.threats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { priority },
          })
        }
      }

      // Update local state immediately for responsiveness
      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return {
                ...cm,
                priority,
                updatedAt: new Date().toISOString(),
              }
            }),
          }
        }),
      }))
    },
    [state.threats, updateCountermeasureMutation]
  )

  // Update countermeasure due date
  const updateCountermeasureDueDate = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, dueDate: string | null) => {
      const threat = state.threats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { dueDate },
          })
        }
      }

      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return { ...cm, dueDate, updatedAt: new Date().toISOString() }
            }),
          }
        }),
      }))
    },
    [state.threats, updateCountermeasureMutation]
  )

  // Update countermeasure external ticket URL
  const updateCountermeasureExternalTicket = useCallback(
    (componentThreatId: string, countermeasureInstanceId: string, externalTicketUrl: string) => {
      const threat = state.threats.find((ct) => ct.id === componentThreatId)
      const countermeasure = threat?.countermeasures.find((cm) => cm.id === countermeasureInstanceId)

      if (countermeasure) {
        const parsed = parseCountermeasureId(countermeasure.id)

        if (parsed.type === 'backend' && parsed.id !== null) {
          updateCountermeasureMutation.mutate({
            countermeasureId: parsed.id,
            data: { externalTicketUrl },
          })
        }
      }

      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            updatedAt: new Date().toISOString(),
            countermeasures: ct.countermeasures.map((cm) => {
              if (cm.id !== countermeasureInstanceId) return cm
              return { ...cm, externalTicketUrl, updatedAt: new Date().toISOString() }
            }),
          }
        }),
      }))
    },
    [state.threats, updateCountermeasureMutation]
  )

  // Update the triage status of one scenario; it shows under every target.
  const updateTriageStatus = useCallback((
    componentThreatId: string,
    triageStatus: TriageStatus,
    decisionRationale?: string
  ) => {
    const threat = state.threats.find((ct) => ct.id === componentThreatId)
    if (threat?.backendThreatId) {
      updateTriageStatusMutation.mutate(
        { threatId: threat.backendThreatId, triageStatus, decisionRationale },
        { onError: (error) => toast.error(writeErrorMessage(error, 'Could not change the triage status')) }
      )
    }
    setState((prev) => ({
      ...prev,
      threats: prev.threats.map((ct) => {
        if (ct.id !== componentThreatId) return ct
        return {
          ...ct,
          triageStatus,
          decisionRationale: decisionRationale ?? ct.decisionRationale,
          updatedAt: new Date().toISOString(),
        }
      }),
    }))
  }, [state.threats, updateTriageStatusMutation])

  // Add custom countermeasure
  const addCountermeasure = useCallback(
    (componentThreatId: string, countermeasureId: string) => {
      setState((prev) => {
        const timestamp = new Date().toISOString()
        return {
          ...prev,
          threats: prev.threats.map((ct) => {
            if (ct.id !== componentThreatId) return ct
            if (ct.countermeasures.some((cm) => cm.countermeasureId === countermeasureId)) {
              return ct
            }
            const newCm: AnalysisCountermeasure = {
              id: `ctcm-${componentThreatId}-${countermeasureId}-${Date.now()}`,
              countermeasureId,
              componentThreatId,
              status: 'gap',
              createdAt: timestamp,
              updatedAt: timestamp,
            }
            return {
              ...ct,
              updatedAt: timestamp,
              countermeasures: [...ct.countermeasures, newCm],
            }
          }),
        }
      })
    },
    []
  )

  // Reorder the threats shown under one tree row: per target when a target
  // is selected, the scenarios' own order for the whole-system list.
  const reorderThreats = useCallback(
    (selection: AnalysisSelection, reorderedThreats: AnalysisThreat[]) => {
      // Update local state immediately with new displayOrder values
      setState((prev) => {
        const reorderedIds = new Set(reorderedThreats.map((t) => t.id))
        const otherThreats = prev.threats.filter((ct) => !reorderedIds.has(ct.id))
        const updatedReordered = reorderedThreats.map((t, index) => ({
          ...t,
          displayOrder: index,
        }))
        return { ...prev, threats: [...otherThreats, ...updatedReordered] }
      })

      const orderedIds = reorderedThreats
        .map((threat) => threatIdFromUiId(threat.id))
        .filter((id): id is number => id !== null)
      if (orderedIds.length > 0) {
        reorderThreatsMutation.mutate(
          selection.kind === 'target'
            ? { orderedIds, targetType: selection.type, targetId: selection.id }
            : { orderedIds }
        )
      }
    },
    [reorderThreatsMutation]
  )

  // Reorder countermeasures for a threat
  const reorderCountermeasures = useCallback(
    (componentThreatId: string, reorderedCountermeasures: AnalysisCountermeasure[]) => {
      // Update local state immediately
      setState((prev) => ({
        ...prev,
        threats: prev.threats.map((ct) => {
          if (ct.id !== componentThreatId) return ct
          return {
            ...ct,
            countermeasures: reorderedCountermeasures.map((cm, index) => ({
              ...cm,
              displayOrder: index,
            })),
          }
        }),
      }))

      // Collect all backend CM IDs and fire single mutation
      const threatId = threatIdFromUiId(componentThreatId)
      const backendCmIds: number[] = []
      for (const cm of reorderedCountermeasures) {
        const parsed = parseCountermeasureId(cm.id)
        if (parsed.type === 'backend' && parsed.id !== null) {
          backendCmIds.push(parsed.id)
        }
      }
      if (threatId !== null && backendCmIds.length > 0) {
        reorderCountermeasuresMutation.mutate({ threatId, orderedIds: backendCmIds })
      }
    },
    [reorderCountermeasuresMutation]
  )

  // Toggle checklist item: no-op since all items are now auto-computed by the backend
  const toggleChecklistItem = useCallback((_itemId: string, _checked: boolean) => {
    // All checklist items are auto-computed by the backend; no local state to update
  }, [])

  // Compute summary statistics
  const summaries = useMemo(() => {
    const activeThreats = state.threats.filter((ct) => isActiveThreat(ct.triageStatus))

    const allNodes = diagrams.filter((d) => d.isPrimary).flatMap((d) => d.canvasData?.nodes || [])

    // Get IDs of components already on canvas to avoid double-counting
    const canvasComponentIds = new Set(
      allNodes
        .map((n) => n.data?.componentId)
        .filter(Boolean)
    )
    // Analysis-only components not already on canvas
    const analysisOnly = analysisComponents.filter((c) => !canvasComponentIds.has(c.id))

    const componentSummary = {
      total: allNodes.filter(
        (n) => n.type === 'process' || n.type === 'datastore' || n.type === 'humanActor' || n.type === 'systemActor'
      ).length + analysisOnly.length,
      processes: allNodes.filter((n) => n.type === 'process').length
        + analysisOnly.filter((c) => c.category === 'process').length,
      datastores: allNodes.filter((n) => n.type === 'datastore').length
        + analysisOnly.filter((c) => c.category === 'datastore').length,
      humanActors: allNodes.filter((n) => n.type === 'humanActor').length
        + analysisOnly.filter((c) => c.category === 'external_human_actor').length,
      systemActors: allNodes.filter((n) => n.type === 'systemActor').length
        + analysisOnly.filter((c) => c.category === 'external_system_actor').length,
      trustZones: allNodes.filter((n) => n.type === 'trustZone').length,
    }

    let exposedThreats = 0
    let addressableThreats = 0
    let mitigatedThreats = 0

    activeThreats.forEach((ct) => {
      const status = deriveThreatStatus(ct.countermeasures)
      if (status === 'exposed') exposedThreats++
      else if (status === 'addressable') addressableThreats++
      else mitigatedThreats++
    })

    const threatSummary = {
      total: activeThreats.length,
      exposed: exposedThreats,
      addressable: addressableThreats,
      mitigated: mitigatedThreats,
    }

    // Each countermeasure counts once even when it mitigates several scenarios.
    const countermeasuresById = new Map<string, AnalysisCountermeasure>()
    activeThreats.forEach((ct) => ct.countermeasures.forEach((cm) => countermeasuresById.set(cm.id, cm)))
    const allCountermeasures = Array.from(countermeasuresById.values())
    const countermeasureSummary = {
      total: allCountermeasures.length,
      platform: allCountermeasures.filter((cm) => cm.status === 'platform').length,
      verified: allCountermeasures.filter((cm) => cm.status === 'verified').length,
      gap: allCountermeasures.filter((cm) => cm.status === 'gap').length,
      planned: allCountermeasures.filter((cm) => cm.status === 'planned').length,
      waived: allCountermeasures.filter((cm) => cm.status === 'waived').length,
    }

    return { componentSummary, threatSummary, countermeasureSummary }
  }, [state.threats, diagrams, analysisComponents])

  // Progress checklist is computed by the backend and returned in workspace_data
  const progressChecklist: ProgressChecklistItem[] = useMemo(() => {
    const workspaceData = threatModel?.workspaceData as Record<string, unknown> | undefined
    const backendChecklist = workspaceData?.progressChecklist as ProgressChecklistItem[] | undefined
    if (backendChecklist?.length) return backendChecklist
    return []
  }, [threatModel?.workspaceData])

  // Enhanced completion status from backend
  const completionStatus: CompletionStatus | undefined = useMemo(() => {
    const workspaceData = threatModel?.workspaceData as Record<string, unknown> | undefined
    return workspaceData?.completionStatus as CompletionStatus | undefined
  }, [threatModel?.workspaceData])

  return {
    threats: state.threats,
    /** @deprecated Use `threats`; kept for the readers the step 15 UI rewrite replaces. */
    componentThreats: state.threats,
    progressChecklist,
    completionStatus,
    summaries,
    isLoading: isLoadingThreats || isLoadingThreatModel,
    isLoadingThreats,
    updateCountermeasureStatus,
    updateCountermeasurePriority,
    updateCountermeasureDueDate,
    updateCountermeasureExternalTicket,
    assignOwner,
    updateTriageStatus,
    addCountermeasure,
    toggleChecklistItem,
    reorderThreats,
    reorderCountermeasures,
  }
}
