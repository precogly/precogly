/**
 * Pure helpers for the Review card (plan 11.5, L5, D18).
 *
 * The backend decides the approval state (`threat_models/review.py`); these
 * helpers only turn it into labels, map the review frequency presets and
 * read the review block an import kept in `formatMetadata.cyclonedx.review`.
 */

import { REVIEW_FREQUENCY_PRESETS } from '@/types/domain'
import type { ApprovalState } from '@/features/threat-models/types/core'

export const APPROVAL_STATE_LABELS: Record<ApprovalState, string> = {
  none: 'Not approved',
  approved: 'Approved',
  changed: 'Changed since approval',
  review_due: 'Review due',
}

export function approvalStateLabel(state: ApprovalState | undefined | null): string {
  if (!state) return APPROVAL_STATE_LABELS.none
  return APPROVAL_STATE_LABELS[state] ?? APPROVAL_STATE_LABELS.none
}

/** Tailwind classes for the state badge; one colour per state. */
export function approvalStateBadgeClass(state: ApprovalState | undefined | null): string {
  switch (state) {
    case 'approved':
      return 'border-green-300 bg-green-50 text-green-700'
    case 'changed':
      return 'border-amber-300 bg-amber-50 text-amber-700'
    case 'review_due':
      return 'border-red-300 bg-red-50 text-red-700'
    default:
      return 'border-gray-300 bg-gray-50 text-gray-600'
  }
}

/** Sentinel values of the review frequency select beside the presets. */
export const REVIEW_FREQUENCY_NONE = 'none'
export const REVIEW_FREQUENCY_CUSTOM = 'custom'

export interface ReviewFrequencySelection {
  /** A preset value (P1M, P3M, P6M, P1Y), `none` or `custom`. */
  preset: string
  /** The ISO 8601 duration when `preset` is `custom`, else empty. */
  custom: string
}

/** Map a stored review frequency to the select's value and the custom text. */
export function reviewFrequencySelection(value: string | undefined | null): ReviewFrequencySelection {
  const stored = (value ?? '').trim()
  if (!stored) return { preset: REVIEW_FREQUENCY_NONE, custom: '' }
  if (REVIEW_FREQUENCY_PRESETS.some((preset) => preset.value === stored)) {
    return { preset: stored, custom: '' }
  }
  return { preset: REVIEW_FREQUENCY_CUSTOM, custom: stored }
}

/** The preset label, the raw duration for a custom value, or "Not set". */
export function reviewFrequencyLabel(value: string | undefined | null): string {
  const stored = (value ?? '').trim()
  if (!stored) return 'Not set'
  return REVIEW_FREQUENCY_PRESETS.find((preset) => preset.value === stored)?.label ?? stored
}

const ISO_8601_DURATION = /^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$/

/** `P3M`, `P1Y`, `P2W`, `P1DT12H` are durations; `3 months` is not. */
export function isIso8601Duration(value: string): boolean {
  return ISO_8601_DURATION.test(value.trim())
}

export interface SourceDocumentApproval {
  approverName: string | null
  approvedAt: string | null
  reviewerName: string | null
  reviewedAt: string | null
}

function partyName(party: unknown): string | null {
  if (typeof party === 'string') return party || null
  if (party && typeof party === 'object') {
    const record = party as Record<string, unknown>
    const name = record.name ?? record.email ?? record.ref
    return typeof name === 'string' && name ? name : null
  }
  return null
}

function dateString(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null
}

/**
 * The review block an import kept (`tmbom/importer/context.py`
 * `import_blueprint_metadata`): `reviewer`, `reviewDate`, `approver`,
 * `approvalDate`, the parties as `{ref, name, email}`. Null when the block
 * carries neither a reviewer nor an approver.
 */
export function sourceDocumentApproval(
  review: Record<string, unknown> | null | undefined
): SourceDocumentApproval | null {
  if (!review) return null
  const result: SourceDocumentApproval = {
    approverName: partyName(review.approver),
    approvedAt: dateString(review.approvalDate),
    reviewerName: partyName(review.reviewer),
    reviewedAt: dateString(review.reviewDate),
  }
  if (!result.approverName && !result.reviewerName && !result.approvedAt && !result.reviewedAt) {
    return null
  }
  return result
}

/** "2 Oct 2026" for a date or datetime string; the raw text when it does not parse. */
export function formatReviewDate(value: string | null | undefined): string {
  if (!value) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

/** `YYYY-MM-DD` for a date input, from a datetime string. */
export function dateInputValue(value: string | null | undefined): string {
  if (!value) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return ''
  return parsed.toISOString().slice(0, 10)
}

/** A date input's value as the ISO datetime the backend's DateTimeField takes, or null when cleared. */
export function dateInputToIso(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return null
  return `${trimmed}T00:00:00Z`
}
