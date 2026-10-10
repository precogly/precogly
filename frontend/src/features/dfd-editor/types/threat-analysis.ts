import type { SecurityStandard, TaxonomyEntry } from '@/types/domain'
import type { Rating, RatingLevel } from '@/types/risk'
import { isActiveThreat, type TriageStatus } from '@/types/triage'

/**
 * Compliance standard mapping from backend.
 * requirement may be null after a compliance pack unimport — snapshot fields
 * (frameworkName, sectionCode, requirementDescription) are preserved.
 */
export interface ComplianceStandardMapping {
  id: number
  requirement?: number | null
  frameworkName: string
  frameworkSlug: string
  sectionCode: string
  requirementDescription: string
  sufficiency: 'full' | 'partial'
}

/**
 * Status of a countermeasure for a specific component-threat
 */
export type CountermeasureStatus = 'platform' | 'gap' | 'planned' | 'in_progress' | 'implemented' | 'verified' | 'waived' | 'decommissioned'

export const COUNTERMEASURE_STATUS_CONFIG: Record<
  CountermeasureStatus,
  { label: string; color: string; bgColor: string; description: string }
> = {
  platform: {
    label: 'Platform',
    color: '#22c55e', // green
    bgColor: 'bg-green-500',
    description: 'Handled at platform/infrastructure level',
  },
  gap: {
    label: 'Gap',
    color: '#ef4444', // red
    bgColor: 'bg-red-500',
    description: 'Not implemented, needs attention',
  },
  planned: {
    label: 'Planned',
    color: '#eab308', // yellow
    bgColor: 'bg-yellow-500',
    description: 'Implementation planned or in progress',
  },
  verified: {
    label: 'Verified',
    color: '#22c55e', // green
    bgColor: 'bg-green-500',
    description: 'Implementation verified by security team',
  },
  waived: {
    label: 'Waived',
    color: '#3b82f6', // blue
    bgColor: 'bg-blue-500',
    description: 'Risk accepted, not implementing',
  },
  in_progress: {
    label: 'In Progress',
    color: '#eab308', // yellow
    bgColor: 'bg-yellow-500',
    description: 'Implementation actively underway',
  },
  implemented: {
    label: 'Implemented',
    color: '#10b981', // teal-green, distinct from verified
    bgColor: 'bg-emerald-500',
    description: 'Implemented, not yet independently verified by the security team',
  },
  decommissioned: {
    label: 'Decommissioned',
    color: '#6b7280', // gray
    bgColor: 'bg-gray-400',
    description: 'Control formally retired, no longer tracked as active',
  },
}

/**
 * Derived status for a threat based on its countermeasures
 */
export type ThreatStatus = 'exposed' | 'addressable' | 'mitigated'

export const THREAT_STATUS_CONFIG: Record<
  ThreatStatus,
  { label: string; color: string; bgColor: string; description: string }
> = {
  exposed: {
    label: 'exposed',
    color: '#ef4444', // red
    bgColor: 'bg-red-100 text-red-700',
    description: 'Threat has unaddressed countermeasures (gaps)',
  },
  addressable: {
    label: 'addressable',
    color: '#eab308', // yellow
    bgColor: 'bg-yellow-100 text-yellow-700',
    description: 'All countermeasures are planned, waived, or platform-level',
  },
  mitigated: {
    label: 'mitigated',
    color: '#22c55e', // green
    bgColor: 'bg-green-100 text-green-700',
    description: 'All countermeasures are implemented or platform-level',
  },
}

/** What a threat or a countermeasure can target (InstanceThreatTarget.TARGET_KINDS). */
export type TargetType = 'component' | 'flow' | 'zone' | 'boundary'

/** A target as the analysis payload places it on the canvas (analysis_service.serialize_targets). */
export interface AnalysisTarget {
  type: TargetType
  id: number
  name: string | null
  blueprintId: number
  /** Canvas node id for a component or zone; `analysis-{id}` for a component on no canvas. */
  nodeId: string | null
  /** Canvas edge id for a flow or boundary; `analysis-flow-{id}` for a flow on no canvas. */
  edgeId: string | null
  dfdId: string | null
  dfdName: string | null
}

/** The canvas id a target is shown under: its node id, its edge id, or null for a zone or boundary on no canvas. */
export function targetCanvasId(target: AnalysisTarget | undefined): string | null {
  if (!target) return null
  return target.nodeId ?? target.edgeId ?? null
}

/** Another scenario a countermeasure is linked to ("Also mitigates", plan 11.3). */
export interface AlsoMitigatesEntry {
  threatId: number
  displayNumber: string
  threatName: string | null
  targets: Array<Pick<AnalysisTarget, 'type' | 'id' | 'name' | 'blueprintId'>>
}

/**
 * A countermeasure attached to a scenario, as the analysis screen holds it.
 * Scope (`targets`) and provider (`implementedBy`) are stored and shown; they
 * never change a threat's status (L4).
 */
export interface AnalysisCountermeasure {
  id: string
  // Reference to countermeasure definition (e.g., "lib-123" for backend)
  countermeasureId: string
  // The UI id of the threat this entry belongs to
  threatId: string
  // Current status
  status: CountermeasureStatus
  // Owner (email or username)
  owner?: string
  // Notes or justification (especially for waived)
  notes?: string
  // Timestamps
  createdAt: string
  updatedAt: string

  // Backend id and number
  backendCountermeasureId?: number
  number?: number
  displayNumber?: string
  autoGenerated?: boolean
  // Where the control applies; empty means the whole system
  targets?: AnalysisTarget[]
  // Components that implement it, and a provider named as text
  implementedBy?: number[]
  implementedByParty?: string
  // Where the control came from (free text)
  source?: string

  // Countermeasure metadata from backend (eliminates need for frontend registry lookup)
  countermeasureName?: string
  countermeasureDescription?: string
  controlFunctions?: string[]
  controlNature?: string
  // Compliance standard mappings from backend
  standardMappings?: ComplianceStandardMapping[]
  // Priority level
  priority?: 'none' | 'low' | 'medium' | 'high' | 'critical'
  // Due date (ISO date string)
  dueDate?: string | null
  // External ticket link (Jira/GitHub/etc.)
  externalTicketUrl?: string
  // Display order for drag-and-drop reordering
  displayOrder?: number
  // Shared countermeasure M2M support
  alsoMitigates?: AlsoMitigatesEntry[]
  isShared?: boolean
}

/**
 * One scenario of the analysis screen. A threat has several targets or is
 * whole-system (plan section 4.1); the tree shows it under each target.
 */
export interface AnalysisThreat {
  /** `threat-{backend id}` (lib/threat-ids.ts). */
  id: string
  // Reference to the diagram the first target sits on (for tracking which DFD this came from)
  diagramId: string
  // Source diagram info (for aggregated view)
  sourceDiagramId?: string
  sourceDiagramTitle?: string
  // Reference to threat definition (e.g., "lib-123"); "custom" when there is none
  threatId: string
  // Triage status for this threat
  triageStatus: TriageStatus
  // Rationale for triage decision
  decisionRationale?: string
  // Custom notes
  notes?: string
  // Countermeasures for this scenario
  countermeasures: AnalysisCountermeasure[]
  // Timestamps
  createdAt: string
  updatedAt: string

  // Identity (plan 4.1)
  backendThreatId: number
  number: number
  /** `T7` for number 7. */
  displayNumber: string
  wholeSystem: boolean
  targets: AnalysisTarget[]
  autoGenerated: boolean
  /** An edited generated scenario the library no longer lists on its targets. */
  libraryMismatch: boolean

  // Threat metadata from backend (eliminates need for frontend registry lookup)
  threatName?: string
  threatDescription?: string
  taxonomyEntries?: TaxonomyEntry[]
  // The rating (#31 comment); null only for rows created outside the API
  rating: Rating | null
  // Display order for drag-and-drop reordering
  displayOrder?: number
  // Context label for display: the first target's name
  componentName?: string
  // Actor & impact fields (one actor rule: a persona or text, never both)
  impactDescription?: string
  threatActorText?: string
  actorPersonaId?: number | null
  actorPersonaName?: string | null
  intent?: string
  accessLevel?: string
  threatSources?: { id: number; name: string; slug?: string }[]
}

/** @deprecated Use `AnalysisCountermeasure`. Kept so readers compile until the step 15 UI rewrite. */
export type ComponentThreatCountermeasure = AnalysisCountermeasure

/** The level a threat is rated at, `medium` when it carries no rating. */
export function threatLevel(threat: Pick<AnalysisThreat, 'rating'>): RatingLevel {
  return threat.rating?.level ?? 'medium'
}

/** Whether a threat targets the given canvas node or edge (any of its targets). */
export function threatTargetsCanvasId(threat: Pick<AnalysisThreat, 'targets'>, canvasId: string): boolean {
  return threat.targets.some((target) => targetCanvasId(target) === canvasId)
}

/**
 * Summary of a component's threat status
 */
export interface ComponentThreatSummary {
  componentId: string
  componentLabel: string
  componentType: string
  technology?: string
  totalThreats: number
  exposedThreats: number
  addressableThreats: number
  mitigatedThreats: number
}

/**
 * Full threat analysis state for a diagram
 */
export interface ThreatAnalysis {
  diagramId: string
  threats: AnalysisThreat[]
  createdAt: string
  updatedAt: string
}

/**
 * Helper to derive threat status from its countermeasures
 */
export function deriveThreatStatus(countermeasures: ComponentThreatCountermeasure[]): ThreatStatus {
  if (countermeasures.length === 0) return 'exposed'

  const hasGaps = countermeasures.some((cm) => cm.status === 'gap')
  if (hasGaps) return 'exposed'

  const hasPlanned = countermeasures.some((cm) => cm.status === 'planned')
  const hasWaived = countermeasures.some((cm) => cm.status === 'waived')
  const hasInProgress = countermeasures.some((cm) => cm.status === 'in_progress')
  if (hasPlanned || hasWaived || hasInProgress) return 'addressable'

  // All are 'platform', 'verified', 'implemented', or 'decommissioned'
  // (no gaps, no planned, no waived, no in_progress)
  return 'mitigated'
}

/**
 * Helper to summarize a component's threat status
 */
export function summarizeComponentThreats(
  componentId: string,
  componentLabel: string,
  componentType: string,
  technology: string | undefined,
  threats: AnalysisThreat[]
): ComponentThreatSummary {
  const analysisThreats = threats.filter(
    (t) => threatTargetsCanvasId(t, componentId) && isActiveThreat(t.triageStatus)
  )

  let exposed = 0
  let addressable = 0
  let mitigated = 0

  analysisThreats.forEach((threat) => {
    const status = deriveThreatStatus(threat.countermeasures)
    if (status === 'exposed') exposed++
    else if (status === 'addressable') addressable++
    else mitigated++
  })

  return {
    componentId,
    componentLabel,
    componentType,
    technology,
    totalThreats: analysisThreats.length,
    exposedThreats: exposed,
    addressableThreats: addressable,
    mitigatedThreats: mitigated,
  }
}

/**
 * Expanded component threat with resolved definitions
 * (For UI display - combines runtime state with library definitions)
 */
export interface ExpandedComponentThreat {
  id: string
  componentId: string
  componentLabel: string
  // Threat definition data
  threatId: string
  threatName: string
  threatDescription: string
  taxonomyEntries?: TaxonomyEntry[]
  // Status derived from countermeasures
  status: ThreatStatus
  triageStatus: TriageStatus
  notes?: string
  // Expanded countermeasures
  countermeasures: ExpandedCountermeasure[]
  createdAt: string
  updatedAt: string
}

/**
 * Expanded countermeasure with resolved definitions
 */
export interface ExpandedCountermeasure {
  id: string
  threatId: string
  // Countermeasure definition data
  countermeasureId: string
  name: string
  description: string
  isPlatformLevel: boolean
  standards: { standard: SecurityStandard; reference?: string }[]
  // Runtime state
  status: CountermeasureStatus
  owner?: string
  notes?: string
  createdAt: string
  updatedAt: string
}

// ============================================
// Workspace Types (for aggregated threat analysis)
// ============================================

/**
 * Asset classification types
 */
export type AssetClassification =
  | 'pii'
  | 'phi'
  | 'financial'
  | 'credentials'
  | 'intellectual_property'
  | 'business_critical'
  | 'public'
  | 'other'

export const ASSET_CLASSIFICATION_CONFIG: Record<AssetClassification, { label: string }> = {
  pii: { label: 'PII (Personal Identifiable Information)' },
  phi: { label: 'PHI (Protected Health Information)' },
  financial: { label: 'Financial Data' },
  credentials: { label: 'Credentials / Secrets' },
  intellectual_property: { label: 'Intellectual Property' },
  business_critical: { label: 'Business Critical' },
  public: { label: 'Public Data' },
  other: { label: 'Other' },
}

/**
 * Asset definition for system context
 */
export interface SystemContextAsset {
  id: string
  name: string
  description: string
  classification: AssetClassification
}

/**
 * Out of scope item definition
 */
export interface SystemContextOutOfScopeItem {
  id: string
  name: string
  reason: string
}

/**
 * System context configuration. The scope lock is gone (#348): assumptions
 * are rows with their own API (features/threat-models/api/threat-models.ts).
 */
export interface SystemContext {
  description?: string
  assets?: SystemContextAsset[]
  outOfScopeItems?: SystemContextOutOfScopeItem[]
}

/**
 * Team member reference
 */
export interface TeamMember {
  id: string
  firstName: string
  lastName: string
  email: string
  role?: string
}

/**
 * Progress checklist item
 */
export interface ProgressChecklistItem {
  id: string
  label: string
  checked: boolean
  autoComputed?: boolean // If true, computed from data rather than manual checkbox
}

/**
 * System definition item for completion status
 */
export interface SystemDefinitionItem {
  id: string
  label: string
  checked: boolean
  count: number
  countLabel: string
}

/**
 * Coverage item for completion status
 */
export interface CoverageItem {
  id: string
  label: string
  numerator: number
  denominator: number
  percentage: number
}

/**
 * A flagged item in a quality signal
 */
export interface QualitySignalFlaggedItem {
  id: number
  name: string
  detail?: string
  componentName?: string
  flowLabel?: string
}

/**
 * Quality signal result
 */
export interface QualitySignal {
  id: string
  status: 'ok' | 'warning'
  okLabel: string
  warningLabel: string
  flaggedItems: QualitySignalFlaggedItem[]
}

/**
 * Enhanced completion status structure
 */
export interface CompletionStatus {
  systemDefinition: SystemDefinitionItem[]
  coverage: CoverageItem[]
  qualitySignals: QualitySignal[]
  /** For the sign-off view: unknown counts as unverified (plan step 9). */
  assumptions?: { total: number; unverified: number }
}

/**
 * Default progress checklist items. Ids follow the backend's completion
 * status (ThreatModelSerializer._compute_completion_status).
 */
export const DEFAULT_PROGRESS_CHECKLIST: Omit<ProgressChecklistItem, 'checked'>[] = [
  { id: 'assets_defined', label: 'Data assets defined', autoComputed: true },
  { id: 'components_identified', label: 'Components identified', autoComputed: true },
  { id: 'trust_boundaries_identified', label: 'Zones and boundaries identified', autoComputed: true },
  { id: 'data_flows_defined', label: 'Flows defined', autoComputed: true },
  { id: 'threats_linked_targets', label: 'Threats linked to components and flows', autoComputed: true },
  { id: 'countermeasures_assigned', label: 'Countermeasures assigned', autoComputed: true },
  { id: 'owners_assigned', label: 'Owners assigned', autoComputed: true },
]

/**
 * Aggregated threat analysis state for a threat model (across all diagrams)
 */
export interface WorkspaceThreatAnalysis {
  threatModelId: string
  threats: AnalysisThreat[]
  systemContext: SystemContext
  progressChecklist: ProgressChecklistItem[]
  completionStatus?: CompletionStatus
  createdAt: string
  updatedAt: string
}
