/**
 * Display helpers for the countermeasure column (plan 11.3): the priority
 * badge classes that lived in severity-utils, the "Also mitigates" line, and
 * the label of a target list.
 */

import type { AlsoMitigatesEntry, AnalysisTarget, CountermeasureStatus } from '../../types/threat-analysis'
import type { TargetRef } from '@/features/threat-models/api/threats'

/** The statuses anyone can pick; `platform` is the Security Team's alone. */
const PICKABLE_STATUSES: CountermeasureStatus[] = ['gap', 'planned', 'verified', 'waived']

/**
 * The statuses a picker offers: platform first for the Security Team, then
 * the four everyone can set. A current status outside that list (platform
 * for other users, or in_progress, implemented and decommissioned from an
 * import) is included too, so a select never shows blank.
 */
export function countermeasureStatusOptions(options: {
  current?: CountermeasureStatus
  isSecurityTeam?: boolean
}): CountermeasureStatus[] {
  const listed: CountermeasureStatus[] = options.isSecurityTeam ? ['platform', ...PICKABLE_STATUSES] : [...PICKABLE_STATUSES]
  if (options.current && !listed.includes(options.current)) listed.unshift(options.current)
  return listed
}

/**
 * What picking a status does: Planned needs an owner first, Waived needs a
 * reason first, anything else is saved as is.
 */
export function countermeasureStatusAction(
  newStatus: CountermeasureStatus,
  hasOwner: boolean
): 'change' | 'assign-owner' | 'waive' {
  if (newStatus === 'planned' && !hasOwner) return 'assign-owner'
  if (newStatus === 'waived') return 'waive'
  return 'change'
}

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

/** Statuses of a control already in effect; such a control is never overdue. */
const IN_EFFECT_STATUSES = new Set(['implemented', 'verified', 'platform'])

/** Today as `YYYY-MM-DD` in the viewer's time zone, the form due dates use. */
export function todayIsoDate(now: Date = new Date()): string {
  const month = String(now.getMonth() + 1).padStart(2, '0')
  const day = String(now.getDate()).padStart(2, '0')
  return `${now.getFullYear()}-${month}-${day}`
}

/**
 * Whether a control is overdue: its due date has passed and it is not yet in
 * effect. The same rule as the backend's `days_overdue` and `?overdue=true`
 * (PR #559), so the column and the API agree.
 */
export function isCountermeasureOverdue(
  countermeasure: { status: string; dueDate?: string | null },
  today: string = todayIsoDate()
): boolean {
  if (!countermeasure.dueDate || IN_EFFECT_STATUSES.has(countermeasure.status)) return false
  return countermeasure.dueDate < today
}

/** Overdue countermeasures by the backend's `days_overdue`, most overdue first. */
export function overdueCountermeasures<Countermeasure extends { daysOverdue: number | null; number: number }>(
  countermeasures: Countermeasure[]
): Countermeasure[] {
  return countermeasures
    .filter((countermeasure) => (countermeasure.daysOverdue ?? 0) > 0)
    .sort((left, right) => (right.daysOverdue ?? 0) - (left.daysOverdue ?? 0) || left.number - right.number)
}
