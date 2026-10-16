/**
 * Pure logic for the "By Use Case" threat analysis view: four columns that
 * follow the chain use case, abuse case, threat, countermeasure. Here: the
 * selection, which use case and abuse cases the first two columns show, the
 * threats of a selection, what "+ Threat" pre-fills, and the search in
 * "Link existing threat".
 */

import { getUseCaseGaps, type UseCaseGap } from '@/features/threat-models/components/use-cases/use-case-utils'
import type { AbuseCase, UseCase } from '@/features/threat-models/types/core'
import type { TargetRef } from '@/features/threat-models/api/threats'
import type { AnalysisThreat } from '../../types/threat-analysis'
import type { ActorValue } from './actor-utils'

// ---- Selection ----

/**
 * What the view has selected: a use case, the "Not linked to a use case"
 * group, or an abuse case. An abuse case can sit under several use cases, so
 * it remembers the one it was picked under (`null` for the group); without
 * that, as from a threat's "From abuse cases" link, its first use case shows.
 */
export type UseCaseViewSelection =
  | { kind: 'useCase'; useCaseId: number }
  | { kind: 'noUseCase' }
  | { kind: 'abuseCase'; abuseCaseId: number; useCaseId?: number | null }

export function useCaseSelectionKey(selection: UseCaseViewSelection | null): string | null {
  if (!selection) return null
  if (selection.kind === 'abuseCase') return `abuse-case:${selection.abuseCaseId}`
  if (selection.kind === 'noUseCase') return 'no-use-case'
  return `${selection.kind}:${selection.useCaseId}`
}

/** The first column's entry: a use case id, the "Not linked" group, or nothing. */
export type UseCaseColumnEntry = { kind: 'useCase'; useCaseId: number } | { kind: 'noUseCase' } | null

/** Which entry of the first column is highlighted, and so whose abuse cases the second column lists. */
export function columnEntryForSelection(selection: UseCaseViewSelection | null, abuseCases: AbuseCase[]): UseCaseColumnEntry {
  if (!selection) return null
  if (selection.kind === 'useCase') return { kind: 'useCase', useCaseId: selection.useCaseId }
  if (selection.kind === 'noUseCase') return { kind: 'noUseCase' }
  if (selection.useCaseId !== undefined) {
    return selection.useCaseId === null ? { kind: 'noUseCase' } : { kind: 'useCase', useCaseId: selection.useCaseId }
  }
  const abuseCase = abuseCases.find((candidate) => candidate.id === selection.abuseCaseId)
  const firstUseCase = abuseCase?.useCases[0]
  return firstUseCase ? { kind: 'useCase', useCaseId: firstUseCase.id } : { kind: 'noUseCase' }
}

/** The abuse cases the second column lists for the first column's entry. */
export function abuseCasesForColumnEntry(entry: UseCaseColumnEntry, tree: UseCaseTree): AbuseCase[] {
  if (!entry) return []
  if (entry.kind === 'noUseCase') return tree.unlinkedAbuseCases
  return tree.useCaseNodes.find((node) => node.useCase.id === entry.useCaseId)?.abuseCases ?? []
}

// ---- Tree ----

export interface UseCaseTreeNode {
  useCase: UseCase
  /** Abuse cases of this use case, in the order returned. */
  abuseCases: AbuseCase[]
  gaps: UseCaseGap[]
}

export interface UseCaseTree {
  useCaseNodes: UseCaseTreeNode[]
  /** Abuse cases with no use case. */
  unlinkedAbuseCases: AbuseCase[]
}

/** An abuse case that realizes no threat gets the "No threat" badge. */
export function abuseCaseHasNoThreat(abuseCase: Pick<AbuseCase, 'threats'>): boolean {
  return abuseCase.threats.length === 0
}

/** Use cases as returned; an abuse case shows under every use case it is linked to. */
export function buildUseCaseTree(useCases: UseCase[], abuseCases: AbuseCase[]): UseCaseTree {
  const useCaseNodes = useCases.map((useCase): UseCaseTreeNode => {
    const children = abuseCases.filter((abuseCase) => abuseCase.useCases.some((linked) => linked.id === useCase.id))
    return {
      useCase,
      abuseCases: children,
      // The badge rule counts the abuse cases actually found, so the badge clears as soon as one is added.
      gaps: getUseCaseGaps({ ...useCase, abuseCaseCount: children.length }),
    }
  })
  const unlinkedAbuseCases = abuseCases.filter((abuseCase) => abuseCase.useCases.length === 0)
  return { useCaseNodes, unlinkedAbuseCases }
}

// ---- Threats of a selection ----

/**
 * The threat rows to list for a selection, matched by backend id against the
 * analysis threats, so a threat is the same row as in the component view.
 * A use case lists the threats of all its abuse cases, each once. Ids with no
 * row (for example filtered out by the page) are skipped.
 */
export function threatsForUseCaseSelection(
  selection: UseCaseViewSelection | null,
  abuseCases: AbuseCase[],
  analysisThreats: AnalysisThreat[]
): AnalysisThreat[] {
  if (!selection || selection.kind === 'noUseCase') return []
  let backendIds: number[] = []
  if (selection.kind === 'abuseCase') {
    const abuseCase = abuseCases.find((candidate) => candidate.id === selection.abuseCaseId)
    backendIds = abuseCase?.threats.map((threat) => threat.id) ?? []
  } else {
    backendIds = abuseCases
      .filter((abuseCase) => abuseCase.useCases.some((linked) => linked.id === selection.useCaseId))
      .flatMap((abuseCase) => abuseCase.threats.map((threat) => threat.id))
  }
  const byBackendId = new Map(analysisThreats.map((threat) => [threat.backendThreatId, threat]))
  const seen = new Set<number>()
  const result: AnalysisThreat[] = []
  for (const backendId of backendIds) {
    if (seen.has(backendId)) continue
    seen.add(backendId)
    const threat = byBackendId.get(backendId)
    if (threat) result.push(threat)
  }
  return result
}

// ---- "+ Threat" pre-fill ----

export interface AddThreatPreset {
  /** Selected targets (the abuse case's own components and flows). */
  initialTargets: TargetRef[]
  /** Offered, not selected: the parent use cases' components and flows, when the abuse case has none. */
  suggestedTargets: TargetRef[]
  initialActor?: ActorValue
}

function targetRefs(parts: { components: { id: number }[]; flows: { id: number }[] }): TargetRef[] {
  return [
    ...parts.components.map((component): TargetRef => ({ type: 'component', id: component.id })),
    ...parts.flows.map((flow): TargetRef => ({ type: 'flow', id: flow.id })),
  ]
}

/**
 * What the add threat dialog starts with for an abuse case:
 * targets and actor from the abuse case; else the use case's components and
 * flows as suggestions; else empty.
 */
export function buildAddThreatPreset(abuseCase: AbuseCase, useCases: UseCase[]): AddThreatPreset {
  const initialTargets = targetRefs(abuseCase)
  const suggestedTargets: TargetRef[] = []
  if (initialTargets.length === 0) {
    const parentIds = new Set(abuseCase.useCases.map((linked) => linked.id))
    const seen = new Set<string>()
    for (const useCase of useCases) {
      if (!parentIds.has(useCase.id)) continue
      for (const ref of targetRefs(useCase)) {
        const key = `${ref.type}:${ref.id}`
        if (seen.has(key)) continue
        seen.add(key)
        suggestedTargets.push(ref)
      }
    }
  }
  const preset: AddThreatPreset = { initialTargets, suggestedTargets }
  if (abuseCase.abuser) preset.initialActor = { actorPersona: abuseCase.abuser.id, threatActorText: '' }
  return preset
}

// ---- Link existing threat ----

/**
 * Threats that can still be linked to an abuse case, matching the query on the
 * T number ("T7" or "7") or the name. An empty query lists them all.
 */
export function filterLinkableThreats(
  threats: Pick<AnalysisThreat, 'backendThreatId' | 'displayNumber' | 'threatName'>[],
  linkedBackendIds: number[],
  query: string
): typeof threats {
  const linked = new Set(linkedBackendIds)
  const needle = query.trim().toLowerCase()
  return threats.filter((threat) => {
    if (linked.has(threat.backendThreatId)) return false
    if (!needle) return true
    return (
      threat.displayNumber.toLowerCase().includes(needle) ||
      (threat.threatName ?? '').toLowerCase().includes(needle)
    )
  })
}
