/**
 * Display labels shared by the report sections, the CSV and Word exports and
 * the pentest scope. Every enum value is read through the labeled lists in
 * types/domain.ts and types/risk.ts, so a value the list does not know falls
 * back to the raw value.
 */

import {
  ASSUMPTION_TOPICS,
  ASSUMPTION_VALIDITY,
  BOUNDARY_TYPES,
  COMPONENT_KINDS,
  FLOW_TYPES,
  LIFECYCLE_PHASES,
  METHODOLOGIES,
  REVIEW_FREQUENCY_PRESETS,
  RISK_DOMAINS,
  ZONE_TYPES,
  ZONE_TYPES_WITH_TRUST_LEVEL,
  type ComponentKind,
  type LabeledValue,
  type ZoneType,
} from '@/types/domain'
import {
  RISK_RESPONSE_STATUSES,
  RISK_RESPONSE_STRATEGIES,
  RISK_STATUSES,
} from '@/types/risk'
import { COUNTERMEASURE_STATUS_CONFIG, THREAT_STATUS_CONFIG } from '@/features/dfd-editor/types/threat-analysis'
import { isAuthenticated, requiresAuthorization } from '@/lib/authentication'
import type { ApprovalState } from '@/features/threat-models/types/core'
import type { ReportBoundary, ReportZone } from '@/features/reports/types/report'

function labelFor<T extends string>(list: readonly LabeledValue<T>[], value: string | null | undefined): string {
  if (!value) return ''
  return list.find((entry) => entry.value === value)?.label ?? value
}

export const zoneTypeLabel = (value: string | null | undefined) => labelFor(ZONE_TYPES, value)
export const boundaryTypeLabel = (value: string | null | undefined) => labelFor(BOUNDARY_TYPES, value)
export const flowTypeLabel = (value: string | null | undefined) => labelFor(FLOW_TYPES, value)
export const componentKindLabel = (value: string | null | undefined) => labelFor(COMPONENT_KINDS, value)
export const assumptionValidityLabel = (value: string | null | undefined) => labelFor(ASSUMPTION_VALIDITY, value)
export const assumptionTopicLabel = (value: string | null | undefined) => labelFor(ASSUMPTION_TOPICS, value)
export const riskStatusLabel = (value: string | null | undefined) => labelFor(RISK_STATUSES, value)
export const riskDomainLabel = (value: string | null | undefined) => labelFor(RISK_DOMAINS, value)
export const responseStrategyLabel = (value: string | null | undefined) => labelFor(RISK_RESPONSE_STRATEGIES, value)
export const responseStatusLabel = (value: string | null | undefined) => labelFor(RISK_RESPONSE_STATUSES, value)
export const lifecyclePhaseLabel = (value: string | null | undefined) => labelFor(LIFECYCLE_PHASES, value)
export const methodologyNameLabel = (value: string | null | undefined) => labelFor(METHODOLOGIES, value)

/** "Quarterly" for P3M; the ISO duration itself for any other value. */
export function reviewFrequencyLabel(value: string | null | undefined): string {
  return labelFor(REVIEW_FREQUENCY_PRESETS, value)
}

export function methodologiesText(methodologies: readonly string[] | null | undefined): string {
  return (methodologies ?? []).map(methodologyNameLabel).join(', ')
}

const RISK_EXPOSURE_LABELS: Record<string, string> = {
  exposed: 'Exposed',
  addressable: 'Addressable',
  mitigated: 'Mitigated',
}

export function riskExposureLabel(value: string | null | undefined): string {
  if (!value) return ''
  return RISK_EXPOSURE_LABELS[value] ?? value
}

export function threatStatusLabel(value: string | null | undefined): string {
  if (!value) return ''
  const config = THREAT_STATUS_CONFIG[value as keyof typeof THREAT_STATUS_CONFIG]
  const label = config?.label ?? value
  return label.charAt(0).toUpperCase() + label.slice(1)
}

export function countermeasureStatusLabel(value: string | null | undefined): string {
  if (!value) return ''
  const config = COUNTERMEASURE_STATUS_CONFIG[value as keyof typeof COUNTERMEASURE_STATUS_CONFIG]
  return config?.label ?? value
}

const APPROVAL_STATE_LABELS: Record<ApprovalState, string> = {
  none: 'Not approved',
  approved: 'Approved',
  changed: 'Changed since approval',
}

export function approvalStateLabel(value: ApprovalState | string | null | undefined): string {
  if (!value) return APPROVAL_STATE_LABELS.none
  return APPROVAL_STATE_LABELS[value as ApprovalState] ?? value
}

/** A date or timestamp as "2 Oct 2026"; the empty string when unset. */
export function formatReportDate(value: string | null | undefined): string {
  if (!value) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

/** The spec kind a component defaults to by its DFD category (backend kind_for_category). */
export function defaultKindForCategory(category: string | null | undefined): ComponentKind {
  switch (category) {
    case 'process':
      return 'process'
    case 'datastore':
      return 'data-store'
    case 'external_human_actor':
    case 'external_system_actor':
      return 'actor'
    default:
      return 'component'
  }
}

/** A zone's trust level text: the number for trust and network zones, "n/a" for the other types. */
export function zoneTrustLevelText(zone: Pick<ReportZone, 'zoneType' | 'trustLevel'>): string {
  if (!ZONE_TYPES_WITH_TRUST_LEVEL.includes(zone.zoneType as ZoneType)) return 'n/a'
  return zone.trustLevel === null || zone.trustLevel === undefined ? 'not set' : String(zone.trustLevel)
}

/** The names in an authentication or authorization list, or "none". */
export function requirementListText(values: readonly string[] | null | undefined): string {
  if (!values || values.length === 0) return 'not recorded'
  return values.join(', ')
}

/**
 * What a flow must satisfy to cross a boundary, in one line (plan I5): the
 * authentication and authorization lists read through the one helper, then
 * the advanced flags that are on.
 */
export function boundaryCrossingRequirementsText(boundary: ReportBoundary): string {
  const parts: string[] = []
  parts.push(
    isAuthenticated(boundary.authentication)
      ? `Authentication: ${boundary.authentication.join(', ')}`
      : 'No authentication required'
  )
  parts.push(
    requiresAuthorization(boundary.authorization)
      ? `Authorization: ${boundary.authorization.join(', ')}`
      : 'No authorization required'
  )
  if (boundary.dataValidation) parts.push('Data validation')
  if (boundary.logging) parts.push('Logging')
  if (boundary.monitoring) parts.push('Monitoring')
  if (boundary.rateLimit) parts.push(`Rate limit: ${boundary.rateLimit}`)
  return parts.join('; ')
}

/** Badge classes per assumption validity, shared by the scope and review sections. */
export const ASSUMPTION_VALIDITY_COLORS: Record<string, string> = {
  verified: 'bg-green-100 text-green-700',
  unverified: 'bg-yellow-100 text-yellow-700',
  unknown: 'bg-yellow-100 text-yellow-700',
  invalid: 'bg-red-100 text-red-700',
}

/** "Whole system" for an empty target list, else the names joined. */
export function targetsText(targets: readonly string[] | null | undefined, wholeSystem = false): string {
  if (wholeSystem || !targets || targets.length === 0) return 'Whole system'
  return targets.join(', ')
}
