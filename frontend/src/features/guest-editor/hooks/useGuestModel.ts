import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type {
  GuestCountermeasure,
  GuestDocumentState,
  GuestTargetRef,
  GuestThreat,
  ThreatStatus,
  GuestRatingLevel,
  ControlFunction,
  ControlNature,
} from '../types'
import type { STRIDECategory } from '@/types/domain'
import { newDocumentState } from '../lib/cyclonedx-guest'
import { removeDiagramElements as applyElementRemoval, removeThreats as applyThreatRemoval } from '../lib/guest-model'

export interface NewThreatInput {
  name: string
  description: string
  level: GuestRatingLevel
  category?: STRIDECategory
  status?: ThreatStatus
  decisionRationale?: string
  targets: GuestTargetRef[]
  wholeSystem: boolean
}

export type ThreatUpdates = Partial<
  Pick<GuestThreat, 'name' | 'description' | 'level' | 'category' | 'status' | 'decisionRationale' | 'targets' | 'wholeSystem'>
>

export interface NewCountermeasureInput {
  threatIds: string[]
  name: string
  description: string
  controlFunction: ControlFunction[]
  controlNature: ControlNature | ''
  targets: GuestTargetRef[]
}

export type CountermeasureUpdates = Partial<
  Pick<GuestCountermeasure, 'threatIds' | 'name' | 'description' | 'controlFunction' | 'controlNature' | 'targets'>
>

export interface LoadedModel {
  threats: GuestThreat[]
  countermeasures: GuestCountermeasure[]
  documentState: GuestDocumentState
}

/**
 * Threats, countermeasures and the document state (identity, counters and
 * kept content) in one place, so the deletion rule (H9) and the number
 * counters (M12) act on both lists at once.
 */
export function useGuestModel() {
  const [threats, setThreats] = useState<GuestThreat[]>([])
  const [countermeasures, setCountermeasures] = useState<GuestCountermeasure[]>([])
  const [documentState, setDocumentState] = useState<GuestDocumentState>(() => newDocumentState())
  // Counters live in a ref so two allocations in one event never hand out the same number.
  const countersRef = useRef({ threat: 1, countermeasure: 1 })
  // The latest lists, for the removal rules that touch both at once.
  const latestRef = useRef({ threats, countermeasures })
  useEffect(() => {
    latestRef.current = { threats, countermeasures }
  }, [threats, countermeasures])

  const allocateThreatNumber = useCallback(() => {
    const number = countersRef.current.threat
    countersRef.current.threat = number + 1
    setDocumentState((previous) => ({ ...previous, nextThreatNumber: number + 1 }))
    return number
  }, [])

  const allocateCountermeasureNumber = useCallback(() => {
    const number = countersRef.current.countermeasure
    countersRef.current.countermeasure = number + 1
    setDocumentState((previous) => ({ ...previous, nextCountermeasureNumber: number + 1 }))
    return number
  }, [])

  const addThreat = useCallback(
    (input: NewThreatInput): GuestThreat => {
      const threat: GuestThreat = {
        id: crypto.randomUUID(),
        number: allocateThreatNumber(),
        name: input.name,
        description: input.description,
        level: input.level,
        ...(input.category ? { category: input.category } : {}),
        status: input.status ?? 'open',
        ...(input.decisionRationale ? { decisionRationale: input.decisionRationale } : {}),
        targets: [...input.targets],
        wholeSystem: input.wholeSystem,
        hiddenTargetRefs: [],
        hiddenBlueprintTargetCount: 0,
        createdAt: new Date().toISOString(),
      }
      setThreats((previous) => [...previous, threat])
      return threat
    },
    [allocateThreatNumber]
  )

  const updateThreat = useCallback((threatId: string, updates: ThreatUpdates) => {
    setThreats((previous) =>
      previous.map((threat) => {
        if (threat.id !== threatId) return threat
        const next = { ...threat, ...updates }
        if (updates.category === undefined && 'category' in updates) delete next.category
        if (updates.decisionRationale === undefined && 'decisionRationale' in updates) delete next.decisionRationale
        return next
      })
    )
  }, [])

  const removeThreat = useCallback((threatId: string) => {
    const result = applyThreatRemoval(latestRef.current.threats, latestRef.current.countermeasures, new Set([threatId]))
    latestRef.current = { threats: result.threats, countermeasures: result.countermeasures }
    setThreats(result.threats)
    setCountermeasures(result.countermeasures)
  }, [])

  const addCountermeasure = useCallback(
    (input: NewCountermeasureInput): GuestCountermeasure => {
      const countermeasure: GuestCountermeasure = {
        id: crypto.randomUUID(),
        number: allocateCountermeasureNumber(),
        threatIds: [...input.threatIds],
        name: input.name,
        description: input.description,
        controlFunction: [...input.controlFunction],
        controlNature: input.controlNature,
        targets: [...input.targets],
        hiddenTargetRefs: [],
        createdAt: new Date().toISOString(),
      }
      setCountermeasures((previous) => [...previous, countermeasure])
      return countermeasure
    },
    [allocateCountermeasureNumber]
  )

  const updateCountermeasure = useCallback((countermeasureId: string, updates: CountermeasureUpdates) => {
    setCountermeasures((previous) =>
      previous.map((countermeasure) => (countermeasure.id === countermeasureId ? { ...countermeasure, ...updates } : countermeasure))
    )
  }, [])

  const removeCountermeasure = useCallback((countermeasureId: string) => {
    setCountermeasures((previous) => previous.filter((countermeasure) => countermeasure.id !== countermeasureId))
  }, [])

  /** The deletion rule (H9) for canvas nodes and edges that are going away. */
  const removeDiagramElements = useCallback((elementIds: Iterable<string>) => {
    const deleted = new Set(elementIds)
    if (deleted.size === 0) return
    const result = applyElementRemoval(latestRef.current.threats, latestRef.current.countermeasures, deleted)
    latestRef.current = { threats: result.threats, countermeasures: result.countermeasures }
    setThreats(result.threats)
    setCountermeasures(result.countermeasures)
  }, [])

  const loadModel = useCallback((loaded: LoadedModel) => {
    latestRef.current = { threats: loaded.threats, countermeasures: loaded.countermeasures }
    setThreats(loaded.threats)
    setCountermeasures(loaded.countermeasures)
    countersRef.current = {
      threat: loaded.documentState.nextThreatNumber,
      countermeasure: loaded.documentState.nextCountermeasureNumber,
    }
    setDocumentState(loaded.documentState)
  }, [])

  const markSaved = useCallback((version: number, digest: string) => {
    setDocumentState((previous) => ({ ...previous, version, exportDigest: digest }))
  }, [])

  const getThreatsForTarget = useCallback(
    (elementId: string) => threats.filter((threat) => threat.targets.some((target) => target.id === elementId)),
    [threats]
  )
  const getWholeSystemThreats = useCallback(() => threats.filter((threat) => threat.wholeSystem), [threats])
  const getThreatCount = useCallback(
    (elementId: string) => threats.filter((threat) => threat.targets.some((target) => target.id === elementId)).length,
    [threats]
  )
  const getAllThreats = useCallback(() => threats, [threats])
  const getCountermeasuresForThreat = useCallback(
    (threatId: string) => countermeasures.filter((countermeasure) => countermeasure.threatIds.includes(threatId)),
    [countermeasures]
  )
  const getCountermeasureCount = useCallback(
    (threatId: string) => countermeasures.filter((countermeasure) => countermeasure.threatIds.includes(threatId)).length,
    [countermeasures]
  )
  const getAllCountermeasures = useCallback(() => countermeasures, [countermeasures])

  return useMemo(
    () => ({
      threats,
      countermeasures,
      documentState,
      addThreat,
      updateThreat,
      removeThreat,
      addCountermeasure,
      updateCountermeasure,
      removeCountermeasure,
      removeDiagramElements,
      loadModel,
      markSaved,
      getThreatsForTarget,
      getWholeSystemThreats,
      getThreatCount,
      getAllThreats,
      getCountermeasuresForThreat,
      getCountermeasureCount,
      getAllCountermeasures,
    }),
    [
      threats,
      countermeasures,
      documentState,
      addThreat,
      updateThreat,
      removeThreat,
      addCountermeasure,
      updateCountermeasure,
      removeCountermeasure,
      removeDiagramElements,
      loadModel,
      markSaved,
      getThreatsForTarget,
      getWholeSystemThreats,
      getThreatCount,
      getAllThreats,
      getCountermeasuresForThreat,
      getCountermeasureCount,
      getAllCountermeasures,
    ]
  )
}

export type GuestModel = ReturnType<typeof useGuestModel>
