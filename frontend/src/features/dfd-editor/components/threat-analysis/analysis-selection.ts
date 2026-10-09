/**
 * What the threat analysis screen has selected in its tree (plan 11.3):
 * the whole system, or one target of the model (a component, flow, zone or
 * boundary by its backend id). Canvas ids play no part any more.
 */

import type { AnalysisThreat, TargetType } from '../../types/threat-analysis'
import type { TargetRef } from '@/features/threat-models/api/threats'

export type AnalysisSelection = { kind: 'system' } | { kind: 'target'; type: TargetType; id: number }

export const SYSTEM_SELECTION: AnalysisSelection = { kind: 'system' }

export function targetSelection(type: TargetType, id: number): AnalysisSelection {
  return { kind: 'target', type, id }
}

/** A stable key for comparisons and React keys: `system`, `component:5`. */
export function selectionKey(selection: AnalysisSelection | null | undefined): string | null {
  if (!selection) return null
  return selection.kind === 'system' ? 'system' : `${selection.type}:${selection.id}`
}

export function targetKey(target: TargetRef): string {
  return `${target.type}:${target.id}`
}

export function isSameSelection(
  left: AnalysisSelection | null | undefined,
  right: AnalysisSelection | null | undefined
): boolean {
  return selectionKey(left) === selectionKey(right)
}

/** The target reference behind a selection, or null for the whole system. */
export function selectionTargetRef(selection: AnalysisSelection | null | undefined): TargetRef | null {
  if (!selection || selection.kind !== 'target') return null
  return { type: selection.type, id: selection.id }
}

/**
 * Whether a scenario shows under a selection: a whole-system threat under
 * "System", a targeted threat under each of its targets.
 */
export function threatMatchesSelection(
  threat: Pick<AnalysisThreat, 'wholeSystem' | 'targets'>,
  selection: AnalysisSelection | null | undefined
): boolean {
  if (!selection) return false
  if (selection.kind === 'system') return threat.wholeSystem
  return threat.targets.some((target) => target.type === selection.type && target.id === selection.id)
}

export const TARGET_TYPE_LABELS: Record<TargetType, string> = {
  component: 'component',
  flow: 'flow',
  zone: 'zone',
  boundary: 'boundary',
}
