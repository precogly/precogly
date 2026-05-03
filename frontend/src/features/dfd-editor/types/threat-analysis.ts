import type { SecurityStandard, TaxonomyEntry } from '@/types/domain'

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
export type CountermeasureStatus = 'platform' | 'gap' | 'planned' | 'verified' | 'waived'

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

/**
 * A countermeasure instance for a specific component-threat pair
 * Includes countermeasure metadata from backend (name, controlType)
 */
export interface ComponentThreatCountermeasure {
  id: string
  // Reference to countermeasure definition (e.g., "lib-123" for backend)
  countermeasureId: string
  // Reference to the component-threat this belongs to
  componentThreatId: string
  // Current status
  status: CountermeasureStatus
  // Owner (email or username)
  owner?: string
  // Notes or justification (especially for waived)
  notes?: string
  // If this countermeasure is provided by a trust boundary (for data flows)
  providedByBoundaryId?: string
  // Timestamps
  createdAt: string
  updatedAt: string

  // Countermeasure metadata from backend (eliminates need for frontend registry lookup)
  countermeasureName?: string
  countermeasureDescription?: string
  controlType?: string
  // Compliance standard mappings from backend
  standardMappings?: ComplianceStandardMapping[]
  // Priority level
  priority?: 'none' | 'low' | 'medium' | 'high' | 'critical'
  // Display order for drag-and-drop reordering
  displayOrder?: number
  // Zone inheritance tracking
  isInherited?: boolean
  inheritedFromComponentName?: string
  inheritedFromZoneName?: string
}

/**
 * A threat instance for a specific component
 * Includes threat metadata from backend (name, description, STRIDE category)
 */
export interface ComponentThreat {
  id: string
  // Reference to the diagram (for tracking which DFD this came from)
  diagramId: string
  // Source diagram info (for aggregated view)
  sourceDiagramId?: string
  sourceDiagramTitle?: string
  // Reference to the component (node ID from the DFD)
  componentId: string
  // Reference to threat definition (e.g., "lib-123")
  threatId: string
  // Whether this threat was dismissed/hidden
  dismissed: boolean
  // Reason for dismissal (if dismissed)
  dismissalReason?: string
  // Custom notes
  notes?: string
  // Countermeasures for this component-threat
  countermeasures: ComponentThreatCountermeasure[]
  // Timestamps
  createdAt: string
  updatedAt: string

  // Threat metadata from backend (eliminates need for frontend registry lookup)
  threatName?: string
  threatDescription?: string
  taxonomyEntries?: TaxonomyEntry[]
  // Severity scoring metadata
  inherentSeverity?: string
  residualSeverity?: string
  severityScoringMetadata?: Record<string, unknown>
  // Display order for drag-and-drop reordering
  displayOrder?: number
  // Backend IDs for API operations
  backendThreatId?: number
  backendComponentId?: number
  threatType?: 'component' | 'dataflow'
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
  componentThreats: ComponentThreat[]
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
  if (hasPlanned || hasWaived) return 'addressable'

  // All are 'platform' or 'verified' (no gaps, no planned, no waived)
  return 'mitigated'
}

const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** Return the higher (worse) of two severity labels for rollup on the canvas. */
export function worseSeverity(a: string | undefined, b: string | undefined): string | undefined {
  const ra = SEVERITY_RANK[String(a ?? '').toLowerCase()] ?? 0
  const rb = SEVERITY_RANK[String(b ?? '').toLowerCase()] ?? 0
  const ta = String(a ?? '').trim()
  const tb = String(b ?? '').trim()
  if (!ta) return tb || undefined
  if (!tb) return ta
  return rb >= ra ? tb : ta
}

/**
 * Helper to summarize a component's threat status
 */
export function summarizeComponentThreats(
  componentId: string,
  componentLabel: string,
  componentType: string,
  technology: string | undefined,
  threats: ComponentThreat[]
): ComponentThreatSummary {
  const componentThreats = threats.filter((t) => t.componentId === componentId && !t.dismissed)

  let exposed = 0
  let addressable = 0
  let mitigated = 0

  componentThreats.forEach((threat) => {
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
    totalThreats: componentThreats.length,
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
  dismissed: boolean
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
  componentThreatId: string
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
 * System context configuration
 */
export interface SystemContext {
  description?: string
  assets?: SystemContextAsset[]
  outOfScopeItems?: SystemContextOutOfScopeItem[]
  scopeLocked: boolean
  scopeLockedAt?: string
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
 * Default progress checklist items
 */
export const DEFAULT_PROGRESS_CHECKLIST: Omit<ProgressChecklistItem, 'checked'>[] = [
  { id: 'assets_defined', label: 'Primary assets defined', autoComputed: true },
  { id: 'components_identified', label: 'Components identified', autoComputed: true },
  { id: 'trust_boundaries_identified', label: 'Trust boundaries identified', autoComputed: true },
  { id: 'data_flows_defined', label: 'Data flows defined', autoComputed: true },
  { id: 'owners_assigned', label: 'Owners assigned', autoComputed: true },
  { id: 'threats_linked_components', label: 'Threats linked to components', autoComputed: true },
  { id: 'threats_linked_flows', label: 'Threats linked to flows', autoComputed: true },
  { id: 'countermeasures_assigned', label: 'Countermeasures assigned', autoComputed: true },
]

/**
 * Aggregated threat analysis state for a threat model (across all diagrams)
 */
export interface WorkspaceThreatAnalysis {
  threatModelId: string
  componentThreats: ComponentThreat[]
  systemContext: SystemContext
  progressChecklist: ProgressChecklistItem[]
  createdAt: string
  updatedAt: string
}
