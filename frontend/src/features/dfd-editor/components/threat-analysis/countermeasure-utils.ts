/**
 * Display helpers for the countermeasure column (plan 11.3): the priority
 * badge classes that lived in severity-utils, the "Also mitigates" line, and
 * the label of a target list.
 */

import type { AlsoMitigatesEntry, AnalysisTarget } from '../../types/threat-analysis'
import type { TargetRef } from '@/features/threat-models/api/threats'

export const PRIORITY_CONFIG: Record<string, { label: string; color: string }> = {
  none: { label: 'None', color: 'bg-gray-100 text-gray-600' },
  low: { label: 'Low', color: 'bg-blue-100 text-blue-700' },
  medium: { label: 'Medium', color: 'bg-yellow-100 text-yellow-700' },
  high: { label: 'High', color: 'bg-orange-100 text-orange-700' },
  critical: { label: 'Critical', color: 'bg-red-100 text-red-700' },
}

/** How many target names a line spells out before "and N more". */
const SHOWN_TARGETS = 2

/**
 * "PLC, Control signals, and 5 more" for a target list; "whole system" for
 * an empty one (a whole-system threat or an unscoped control).
 */
export function formatTargetList(
  targets: Array<Pick<AnalysisTarget, 'name'> | { name: string | null }>,
  shown: number = SHOWN_TARGETS
): string {
  const names = targets.map((target) => target.name || 'Unnamed')
  if (names.length === 0) return 'whole system'
  if (names.length <= shown) return names.join(', ')
  const rest = names.length - shown
  return `${names.slice(0, shown).join(', ')}, and ${rest} more`
}

/**
 * One line per other linked threat (plan 11.3 "Also mitigates"):
 * "T12 API Gateway Input Injection (API Gateway, Filtered request, and 5 more)".
 */
export function formatAlsoMitigatesLine(entry: AlsoMitigatesEntry): string {
  const name = entry.threatName || 'Unnamed threat'
  return `${entry.displayNumber} ${name} (${formatTargetList(entry.targets)})`
}

/** Whether two target lists name the same targets (order ignored). */
export function sameTargets(left: TargetRef[], right: TargetRef[]): boolean {
  if (left.length !== right.length) return false
  const keys = new Set(left.map((target) => `${target.type}:${target.id}`))
  return right.every((target) => keys.has(`${target.type}:${target.id}`))
}

/** The effectiveness input's text: an integer percentage or "" for not assessed. */
export function effectivenessToInput(effectiveness: number | null | undefined): string {
  return effectiveness === null || effectiveness === undefined ? '' : String(effectiveness)
}

/** Parse the effectiveness input back: "" is "not assessed" (null); otherwise 0 to 100. */
export function effectivenessFromInput(raw: string): number | null | undefined {
  const trimmed = raw.trim()
  if (trimmed === '') return null
  const parsed = Number(trimmed)
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100) return undefined
  return Math.round(parsed)
}
