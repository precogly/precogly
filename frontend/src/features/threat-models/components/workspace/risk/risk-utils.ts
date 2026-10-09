/**
 * Pure helpers for the risk tab (plan 11.4): board grouping by lifecycle
 * status, the threat picker label, exposure and status display, and the
 * error text a toast shows for a rejected write.
 */

import { ApiError } from '@/lib/api'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import {
  RISK_STATUSES,
  type Risk,
  type RiskExposure,
  type RiskStatus,
} from '@/types/risk'

/** The six board columns, in lifecycle order. */
export const RISK_BOARD_COLUMNS: { status: RiskStatus; label: string; className: string }[] = [
  { status: 'identified', label: 'Identified', className: 'border-gray-300 bg-gray-50' },
  { status: 'assessed', label: 'Assessed', className: 'border-blue-300 bg-blue-50' },
  { status: 'mitigated', label: 'Mitigated', className: 'border-green-300 bg-green-50' },
  { status: 'accepted', label: 'Accepted', className: 'border-purple-300 bg-purple-50' },
  { status: 'transferred', label: 'Transferred', className: 'border-yellow-300 bg-yellow-50' },
  { status: 'retired', label: 'Retired', className: 'border-slate-300 bg-slate-100' },
]

export const RISK_STATUS_CLASSES: Record<RiskStatus, string> = {
  identified: 'bg-gray-100 text-gray-800 border-gray-200',
  assessed: 'bg-blue-100 text-blue-800 border-blue-200',
  mitigated: 'bg-green-100 text-green-800 border-green-200',
  accepted: 'bg-purple-100 text-purple-800 border-purple-200',
  transferred: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  retired: 'bg-slate-100 text-slate-700 border-slate-200',
}

export const RISK_STATUS_LABELS: Record<RiskStatus, string> = Object.fromEntries(
  RISK_STATUSES.map((entry) => [entry.value, entry.label])
) as Record<RiskStatus, string>

/** Exposure is derived from the linked threats (services.derive_risk_status). */
export const RISK_EXPOSURE_LABELS: Record<RiskExposure, string> = {
  exposed: 'Exposed',
  addressable: 'Addressable',
  mitigated: 'Mitigated',
}

export const RISK_EXPOSURE_CLASSES: Record<RiskExposure, string> = {
  exposed: 'bg-red-50 text-red-700 border-red-200',
  addressable: 'bg-amber-50 text-amber-700 border-amber-200',
  mitigated: 'bg-green-50 text-green-700 border-green-200',
}

/** The backend's methodology guard text (threat_models/serializers.py validate_scoring_method_change). */
export const METHODOLOGY_GUARD_MESSAGE =
  'Delete or re-rate existing risks before changing the methodology.'

/**
 * Group one page of risks into the six board columns. Every status gets an
 * entry (possibly empty) so a column can render even when nothing is in it;
 * a risk with an unknown status is dropped rather than shown twice.
 */
export function groupRisksByStatus<RiskLike extends Pick<Risk, 'status'>>(
  risks: RiskLike[]
): Record<RiskStatus, RiskLike[]> {
  const grouped = Object.fromEntries(
    RISK_BOARD_COLUMNS.map((column) => [column.status, [] as RiskLike[]])
  ) as Record<RiskStatus, RiskLike[]>
  for (const risk of risks) {
    const column = grouped[risk.status]
    if (column) column.push(risk)
  }
  return grouped
}

/** What a threat row in the picker and the linked list needs. */
export interface ThreatPickerEntry {
  threatId: number
  displayNumber: string
  threatName: string | null | undefined
  wholeSystem: boolean
  targets: { name: string | null | undefined }[]
}

/** The picker rows from the analysis payload: active threats with a backend id. */
export function threatPickerEntries(componentThreats: ComponentThreat[]): ThreatPickerEntry[] {
  return componentThreats
    .filter((threat) => isActiveThreat(threat.triageStatus) && threat.backendThreatId)
    .map((threat) => ({
      threatId: threat.backendThreatId,
      displayNumber: threat.displayNumber,
      threatName: threat.threatName,
      wholeSystem: threat.wholeSystem,
      targets: threat.targets,
    }))
}

/**
 * `T7 Name (target, target)`; a whole-system threat says so in the brackets,
 * and a threat with no name falls back to its number alone.
 */
export function threatPickerLabel(entry: ThreatPickerEntry): string {
  const name = entry.threatName?.trim() || `Threat ${entry.displayNumber}`
  const targetNames = entry.targets
    .map((target) => target.name?.trim())
    .filter((targetName): targetName is string => Boolean(targetName))
  const scope = entry.wholeSystem
    ? 'whole system'
    : targetNames.length > 0
      ? targetNames.join(', ')
      : ''
  return scope ? `${entry.displayNumber} ${name} (${scope})` : `${entry.displayNumber} ${name}`
}

/**
 * Whether a picker entry matches a free-text filter: the number (`T7`),
 * the name or any target name, case-insensitively.
 */
export function threatPickerMatches(entry: ThreatPickerEntry, filter: string): boolean {
  const needle = filter.trim().toLowerCase()
  if (!needle) return true
  return threatPickerLabel(entry).toLowerCase().includes(needle)
}

/**
 * The message a toast shows for a failed write. DRF answers validation
 * errors as `{field: [messages]}` or `{detail: message}`; anything else
 * falls back to the given default.
 */
export function apiErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError) || !error.data || typeof error.data !== 'object') return fallback
  const data = error.data as Record<string, unknown>
  const messages = Object.entries(data).flatMap(([field, value]) => {
    const texts = Array.isArray(value) ? value.map(String) : [String(value)]
    return field === 'detail' || field === 'nonFieldErrors' ? texts : texts.map((text) => `${field}: ${text}`)
  })
  return messages.length > 0 ? messages.join(' ') : fallback
}

/** A `YYYY-MM-DD` target date for display, or a dash when there is none. */
export function formatTargetDate(targetDate: string | null | undefined): string {
  if (!targetDate) return '-'
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(targetDate)
  if (!match) return targetDate
  const [, year, month, day] = match
  const date = new Date(Number(year), Number(month) - 1, Number(day))
  if (Number.isNaN(date.getTime())) return targetDate
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}
