import type { STRIDECategory, AssumptionValidity } from '@/types/domain'
import { ASSUMPTION_VALIDITY } from '@/types/domain'
import type { RatingLevel } from '@/types/risk'

/**
 * The guest editor's data model (plan section 11.9).
 *
 * A threat sits on several targets, on a zone or boundary, or on the whole
 * system; a countermeasure is linked to several threats and has its own
 * scope. Both carry numbers that are never reused. Everything the guest
 * editor does not model travels as passthrough and is written back on save.
 */

export type ThreatStatus = 'open' | 'accept' | 'mitigate' | 'delegate' | 'eliminate'

/** The four target kinds, named as the backend names them. */
export type GuestTargetType = 'component' | 'flow' | 'zone' | 'boundary'

export interface GuestTargetRef {
  /** The canvas node id (component, zone) or edge id (flow, boundary). */
  id: string
  type: GuestTargetType
}

/** Level-only rating, with `info` (plan 11.9). */
export type GuestRatingLevel = RatingLevel

export const GUEST_RATING_LEVELS: { value: GuestRatingLevel; label: string }[] = [
  { value: 'info', label: 'Info' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

/** Keys and values an opened file carried that the guest editor does not model. */
export type GuestPassthrough = Record<string, unknown>

export interface GuestThreat {
  id: string
  /** T<number>. Allocated from the document counter, never reused (M12). */
  number: number
  name: string
  description: string
  level: GuestRatingLevel
  category?: STRIDECategory
  status: ThreatStatus
  decisionRationale?: string
  /** Targets on this diagram. Empty with `wholeSystem` false only while hidden targets remain. */
  targets: GuestTargetRef[]
  /** A whole-system threat is a flag, never an empty target list (H9). */
  wholeSystem: boolean
  /** Refs the file named that are not on this diagram (another blueprint, a hidden element). */
  hiddenTargetRefs: string[]
  /** How many of the hidden refs point into another blueprint (G8, L10). */
  hiddenBlueprintTargetCount: number
  createdAt: string
  /** The scenario's bom-ref when it came from a file, so it stays stable. */
  bomRef?: string
  /** The abstract threat refs the scenario realizes, in file order. */
  abstractRefs?: string[]
  /** Scenario keys and properties the guest editor does not model. */
  passthrough?: GuestPassthrough
}

export type ControlFunction = 'preventive' | 'detective' | 'corrective' | 'deterrent' | 'recovery' | 'compensating'
export type ControlNature = 'technical' | 'administrative' | 'physical'

export interface GuestCountermeasure {
  id: string
  /** C<number>. Allocated from the document counter, never reused. */
  number: number
  /** Several threats per countermeasure (#529). */
  threatIds: string[]
  name: string
  description: string
  /** May be empty for a control from a file that names none; the dialog asks for one. */
  controlFunction: ControlFunction[]
  /** Empty for a control from a file that names none. */
  controlNature: ControlNature | ''
  /** What the control applies to. Empty means the whole system (as the backend reads it). */
  targets: GuestTargetRef[]
  /** `appliesTo` refs that are not on this diagram. */
  hiddenTargetRefs: string[]
  createdAt: string
  bomRef?: string
  passthrough?: GuestPassthrough
}

export const GUEST_CONTROL_FUNCTIONS = [
  { value: 'preventive' as const, label: 'Preventive', description: 'Stops an attack or fault from occurring. E.g. input validation, access control, encryption at rest.' },
  { value: 'detective' as const, label: 'Detective', description: 'Identifies an attack or fault during or after the fact. E.g. audit logging, intrusion detection, anomaly alerting.' },
  { value: 'corrective' as const, label: 'Corrective', description: 'Limits damage and fixes the problem once detected. E.g. applying a patch, revoking a compromised token.' },
  { value: 'deterrent' as const, label: 'Deterrent', description: 'Discourages a threat actor from attempting an attack. E.g. warning banners, visible monitoring, legal notices.' },
  { value: 'recovery' as const, label: 'Recovery', description: 'Restores systems or data to normal after an incident. E.g. restoring from backup, failover, disaster-recovery procedures.' },
  { value: 'compensating' as const, label: 'Compensating', description: 'Alternative control when the primary is not feasible. E.g. enforced manual review where automated gating is unavailable.' },
] as const

export const GUEST_CONTROL_NATURES = [
  { value: 'technical' as const, label: 'Technical', description: 'Implemented in software, firmware, or hardware and enforced by the system. E.g. firewall rules, cryptographic controls, ACLs.' },
  { value: 'administrative' as const, label: 'Administrative / Procedural', description: 'Implemented through policies, processes, and human behaviour. E.g. secure-coding standards, code-review steps, security training.' },
  { value: 'physical' as const, label: 'Physical', description: 'Implemented through physical-world barriers and safeguards. E.g. locked server rooms, badge readers, tamper-evident seals.' },
] as const

// --- System Context types ---

export interface GuestSessionMetadata {
  facilitator: string
  participants: string[]
  meetingDate: string // ISO date (YYYY-MM-DD) or empty
}

export interface GuestSystemInfo {
  description: string
  criticality: 'low' | 'medium' | 'high' | 'critical'
}

export interface GuestDataAsset {
  id: string
  name: string
  description: string
  classification: string
  confidentiality: 'low' | 'medium' | 'high'
  integrity: 'low' | 'medium' | 'high'
  availability: 'low' | 'medium' | 'high'
  complianceTags: string[]
  dataSensitivity: string[]
  bomRef?: string
  passthrough?: GuestPassthrough
}

export interface GuestAssumption {
  id: string
  description: string
  /** The spec's four validity values. */
  validity: AssumptionValidity
  /** One spec topic, or empty. A custom topic object from a file is kept in passthrough. */
  topic: string
  bomRef?: string
  passthrough?: GuestPassthrough
}

export interface GuestOutOfScopeItem {
  id: string
  name: string
  reason: string
}

export interface GuestSystemContext {
  session: GuestSessionMetadata
  systemInfo: GuestSystemInfo
  dataAssets: GuestDataAsset[]
  assumptions: GuestAssumption[]
  outOfScopeItems: GuestOutOfScopeItem[]
}

/**
 * The document's identity, counters and everything kept for write-back
 * (plan 11.9: serial number, version, the two counters, further blueprints,
 * unknown sections).
 */
export interface GuestDocumentState {
  /** `urn:uuid:...`, created once and kept across saves (I4). */
  serialNumber: string
  /** Raised on save when the content changed. */
  version: number
  /** Digest of the last written or opened content; null for a new document. */
  exportDigest: string | null
  nextThreatNumber: number
  nextCountermeasureNumber: number
  /** Everything the file carried that the guest editor does not model. */
  kept: GuestKeptContent
}

export interface GuestKeptContent {
  /** Top-level sections and keys other than the ones the guest editor writes. */
  document: Record<string, unknown>
  /** `metadata` keys other than timestamp and tools. */
  metadata: Record<string, unknown>
  /** The whole `metadata.component` as it arrived (name and parties included). */
  metadataComponent: Record<string, unknown> | null
  /** Document-level properties, in order, for order-preserving write-back. */
  documentProperties: { name: string; value?: string }[]
  /** The first blueprint's keys the guest editor does not regenerate. */
  blueprint: Record<string, unknown>
  /** The first blueprint's bom-ref, name and model types. */
  blueprintRef: string | null
  blueprintModelTypes: unknown[] | null
  /** Blueprints after the first, written back unchanged (G8). */
  extraBlueprints: unknown[]
  /** First-blueprint entries that are not on the diagram, by section, written back whole. */
  hiddenEntries: Record<string, Record<string, unknown>[]>
  /** The bom-refs of each section's entries in file order, so a save keeps the order. */
  entryOrder: Record<string, string[]>
  /** Unknown keys and properties of each diagram element's entry, by bom-ref. */
  entries: Record<string, Record<string, unknown>>
  /** `threats` section keys other than threats, scenarios and trustBoundaries. */
  threatsSection: Record<string, unknown>
  /** Abstract threats by bom-ref, as they arrived. */
  abstractThreats: Record<string, Record<string, unknown>>
  abstractThreatOrder: string[]
  /** Trust boundary entries by boundary ref, as they arrived. */
  trustBoundaries: Record<string, Record<string, unknown>>
  /** The Precogly visualization entry's keys other than the attachment. */
  visualization: Record<string, unknown> | null
  /** Canvas keys other than nodes and edges (snake_case, as stored). */
  canvasExtras: Record<string, unknown>
  /** Scope keys other than the ones regenerated. */
  scope: Record<string, unknown>
  /** Whether the file carried a scope object at all. */
  hadScope: boolean
}

export function emptyKeptContent(): GuestKeptContent {
  return {
    document: {},
    metadata: {},
    metadataComponent: null,
    documentProperties: [],
    blueprint: {},
    blueprintRef: null,
    blueprintModelTypes: null,
    extraBlueprints: [],
    hiddenEntries: {},
    entryOrder: {},
    entries: {},
    threatsSection: {},
    abstractThreats: {},
    abstractThreatOrder: [],
    trustBoundaries: {},
    visualization: null,
    canvasExtras: {},
    scope: {},
    hadScope: false,
  }
}

export const GUEST_CRITICALITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
] as const

export const GUEST_CIA_LEVELS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
] as const

/** The spec's assumption validity vocabulary (plan 11.9). */
export const GUEST_ASSUMPTION_VALIDITY = ASSUMPTION_VALIDITY

export const GUEST_THREAT_STATUS_OPTIONS = [
  { value: 'open', label: 'Open', description: 'Not yet triaged. Needs a decision' },
  { value: 'accept', label: 'Accept', description: 'Risk is tolerable. No action needed' },
  { value: 'mitigate', label: 'Mitigate', description: 'Reduce risk with countermeasures' },
  { value: 'delegate', label: 'Delegate', description: 'Transfer risk to another party' },
  { value: 'eliminate', label: 'Eliminate', description: 'Remove the threat source entirely' },
] as const

export const RATIONALE_REQUIRED_STATUSES: ThreatStatus[] = ['accept', 'delegate', 'eliminate']

export const STATUS_COLORS: Record<ThreatStatus, string> = {
  open: 'bg-gray-100 text-gray-800',
  accept: 'bg-yellow-100 text-yellow-800',
  mitigate: 'bg-green-100 text-green-800',
  delegate: 'bg-purple-100 text-purple-800',
  eliminate: 'bg-blue-100 text-blue-800',
}

export const LEVEL_COLORS: Record<GuestRatingLevel, string> = {
  info: 'bg-slate-100 text-slate-700',
  low: 'bg-blue-100 text-blue-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
}

export function threatDisplayNumber(threat: Pick<GuestThreat, 'number'>): string {
  return `T${threat.number}`
}

export function countermeasureDisplayNumber(countermeasure: Pick<GuestCountermeasure, 'number'>): string {
  return `C${countermeasure.number}`
}

/** Whether a threat names the given canvas element as a target. */
export function threatTargetsElement(threat: GuestThreat, elementId: string): boolean {
  return threat.targets.some((target) => target.id === elementId)
}

export function getThreatWarning(
  threat: GuestThreat,
  countermeasureCount: number
): string | null {
  if (
    RATIONALE_REQUIRED_STATUSES.includes(threat.status) &&
    !threat.decisionRationale?.trim()
  ) {
    return `Decision rationale recommended for "${threat.status}" status`
  }
  if (threat.status === 'mitigate' && countermeasureCount === 0) {
    return 'Status is "mitigate" but no countermeasures defined'
  }
  return null
}
