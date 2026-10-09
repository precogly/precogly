/**
 * The report payload: GET /threat-models/{id}/report/
 * (backend/apps/threat_models/report_service.py build_report_data).
 */

import type { AssumptionTopic, AssumptionValidity, BoundaryType, ComponentKind, FlowType, ZoneType } from '@/types/domain'
import type { RiskDomain } from '@/types/domain'
import type { RatingLevel } from '@/types/risk'
import type { ApprovalState } from '@/features/threat-models/types/core'

export type ReportType = 'executive' | 'technical' | 'compliance' | 'full'

/** The review block of the report metadata (`report_service._review`). */
export interface ReportReview {
  approvalState: ApprovalState
  reviewer: string | null
  reviewedAt: string | null
  approver: string | null
  approvedAt: string | null
  sourceDocumentReview: Record<string, unknown> | null
}

export interface ReportMetadata {
  name: string
  description: string
  criticality: string
  riskScoringMethod: string
  methodologies: string[]
  owningTeam: string | null
  createdBy: string | null
  createdAt: string | null
  updatedAt: string | null
  frameworks: Array<{
    name: string
    slug: string
    version: string
  }>
  lifecyclePhase: string
  validFrom: string | null
  validUntil: string | null
  reviewFrequency: string
  review: ReportReview
}

/** An assumption row (plan step 9); `owner` is an email or a free-text name. */
export interface ReportAssumption {
  id: number
  blueprint: string
  description: string
  topic: AssumptionTopic | ''
  validity: AssumptionValidity
  impact: string
  owner: string
  validationMethod: string
  validationDate: string | null
  components: string[]
}

export interface ReportBusinessObjective {
  id: number
  name: string
  description: string
  criticality: string
  owner: string
  threatCount: number
  riskCount: number
}

export interface ReportScope {
  description: string
  assumptions: ReportAssumption[]
  businessObjectives: ReportBusinessObjective[]
  outOfScopeItems: Array<{
    id: number
    name: string
    reason: string
  }>
  referencedModels: Array<{
    id: string
    name: string
    relationType: string
  }>
}

export interface ReportZone {
  id: number
  name: string
  zoneType: ZoneType
  /** null when not set */
  trustLevel: number | null
  description: string
}

export interface ReportBoundary {
  id: number
  label: string
  boundaryType: BoundaryType
  zoneA: string
  zoneB: string
  description: string
  authentication: string[]
  authorization: string[]
  requiresAuthentication: boolean
  requiresAuthorization: boolean
  dataValidation: boolean
  logging: boolean
  monitoring: boolean
  rateLimit: string
}

export interface ReportArchitecture {
  dfds: Array<{
    id: string
    name: string
    diagramType: string
    isPrimary?: boolean
    nodeCount: number
    edgeCount: number
    canvasData?: { nodes?: unknown[]; edges?: unknown[]; notationStyle?: string }
  }>
  referenceImages: Array<{
    id: number
    filename: string
    description: string
  }>
  zones: ReportZone[]
  boundaries: ReportBoundary[]
}

export interface ReportDataAsset {
  id: number
  name: string
  description: string
  classification: string
  confidentiality: string
  integrity: string
  availability: string
  placements: Array<{
    componentName: string
    dataState: string
    volume: string
    encrypted: boolean
  }>
  inTransit: Array<{
    flowLabel: string
    protectionMethod: string
    encryptionType: string
  }>
}

export interface ReportComponent {
  id: number
  name: string
  category: string
  /** The spec kind; the backend does not send it yet, so readers default it from `category`. */
  kind?: ComponentKind
  componentType: string
  actorType: string
  provider: string
  zone: string | null
  description: string
}

export interface ReportComponents {
  processes: ReportComponent[]
  dataStores: ReportComponent[]
  humanActors: ReportComponent[]
  systemActors: ReportComponent[]
}

export interface ReportFlow {
  id: number
  label: string
  source: string | null
  destination: string | null
  protocol: string
  encrypted: boolean
  flowType: FlowType
  /** Read it with `isAuthenticated` from lib/authentication.ts (I5). */
  authentication: string[]
  authorization: string[]
  requiresAuthentication: boolean
  crossesBoundary: boolean
  hasSensitiveData: boolean
}

/** @deprecated Use `ReportFlow`. */
export type ReportDataFlow = ReportFlow

export interface ReportComplianceStandard {
  frameworkName: string
  sectionCode: string
  sufficiency: string
}

export interface ReportCountermeasure {
  id: number
  countermeasureName: string
  controlFunctions: string[]
  controlNature: string
  status: string
  priority: string
  assignedOwnerEmail: string | null
  verifiedByEmail: string | null
  evidenceUrl: string
  number: number
  /** `C3` */
  displayNumber: string
  /** Names of the targets the control applies to; empty means the whole system. */
  scope: string[]
  implementedByParty: string
  source: string
  complianceStandards?: ReportComplianceStandard[]
}

/** A rating in the report (`report_service._rating`). */
export interface ReportRating {
  level: RatingLevel
  score: number | null
  methodology: string
  likelihoodLevel: string | null
  likelihoodScore: number | null
  impactLevel: string | null
  impactScore: number | null
  rationale: string
}

export interface ReportThreatTaxonomyEntry {
  taxonomySlug: string
  externalId: string
  title: string
  referenceUrl?: string
}

export interface ReportThreat {
  id: number
  number: number
  /** `T7` */
  displayNumber: string
  wholeSystem: boolean
  /** Names of the targets, in target order. */
  targets: string[]
  threatName: string
  threatDescription: string
  strideCategory: string | null
  businessObjectives: string[]
  taxonomyEntries?: ReportThreatTaxonomyEntry[]
  rating: ReportRating | null
  status: string
  impactDescription: string
  threatActorText: string
  countermeasures: ReportCountermeasure[]
}

export interface ReportTriagedThreat {
  id: number
  number: number
  displayNumber: string
  threatName: string
  targets: string[]
  triageStatus: string
  decisionRationale: string
}

export interface ReportThreatAnalysis {
  strideSummary: Record<string, number>
  /** Every active scenario once, with its targets. */
  threats: ReportThreat[]
  triagedThreats: ReportTriagedThreat[]
}

export interface ReportGap {
  id: string
  countermeasureName: string
  /** `C3` */
  controlNumber: string
  priority: string
  assignedOwnerEmail: string | null
  /** Names of the first linked threat's targets. */
  targets: string[]
  /** The first linked threat's `T7`. */
  displayNumber: string | null
}

export interface ReportWaived {
  id: string
  countermeasureName: string
  controlNumber: string
  targets: string[]
  displayNumber: string | null
}

/** A control with no threat link (I3): listed on its own, out of gap and coverage figures. */
export interface ReportUnattachedControl {
  id: string
  countermeasureName: string
  controlNumber: string
  status: string
  autoGenerated: boolean
  scope: string[]
}

export interface ReportCountermeasureSummary {
  statusBreakdown: Record<string, number>
  gaps: ReportGap[]
  waived: ReportWaived[]
  unattached: ReportUnattachedControl[]
}

export interface ReportRiskResponse {
  id: number
  strategy: string
  status: string
  description: string
  priority: string
  cost: string
  ownerEmail: string | null
  targetDate: string | null
  /** `C` numbers of the controls the response relies on. */
  countermeasures: string[]
}

export interface ReportRisk {
  id: number
  name: string
  description: string
  status: string
  statement: string
  exposure: string
  businessObjectives: string[]
  domains: RiskDomain[]
  inherent: ReportRating | null
  residual: ReportRating | null
  target: ReportRating | null
  responses: ReportRiskResponse[]
  ownerEmail: string | null
  contributingThreats: Array<{
    threatId: number
    displayNumber: string
    threatName: string
    status: string
    targets: string[]
  }>
}

export interface ReportComplianceFramework {
  name: string
  slug: string
  totalRequirements: number
  coveredRequirements: number
  coveragePercentage: number
  satisfiedRequirements: number
  satisfactionPercentage: number
}

export interface ReportCrossFrameworkMappingEntry {
  fromSectionCode: string
  fromDescription: string
  toSectionCode: string
  toDescription: string
  sufficiency: 'full' | 'partial'
}

export interface ReportCrossFrameworkMappingGroup {
  sourceFramework: string
  targetFramework: string
  mappings: ReportCrossFrameworkMappingEntry[]
}

export interface ReportCompliance {
  frameworks: ReportComplianceFramework[]
  crossFrameworkMappings?: ReportCrossFrameworkMappingGroup[]
}

export interface ReportSummaryMetrics {
  totalActiveThreats: number
  totalTriagedThreats: number
  threatsByStatus: Record<string, number>
  totalCountermeasures: number
  countermeasuresByStatus: Record<string, number>
  totalGaps: number
  totalWaived: number
  totalUnattached: number
  totalRisks: number
  /** By residual level, else inherent; includes `info`. */
  risksByLevel: Record<string, number>
}

export interface ReportProgressItem {
  id: string
  label: string
  checked: boolean
  autoComputed: boolean
}

export interface ReportSystemDefinitionItem {
  id: string
  label: string
  checked: boolean
  count: number
  countLabel: string
}

export interface ReportCoverageItem {
  id: string
  label: string
  numerator: number
  denominator: number
  percentage: number
}

export interface ReportQualitySignalFlaggedItem {
  id: number
  name: string
  detail?: string
}

export interface ReportQualitySignal {
  id: string
  status: 'ok' | 'warning'
  okLabel: string
  warningLabel: string
  flaggedItems: ReportQualitySignalFlaggedItem[]
}

export interface ReportCompletionStatus {
  systemDefinition: ReportSystemDefinitionItem[]
  coverage: ReportCoverageItem[]
  qualitySignals: ReportQualitySignal[]
  assumptions?: { total: number; unverified: number }
}

export interface ReportData {
  metadata: ReportMetadata
  scope: ReportScope
  architecture: ReportArchitecture
  dataAssets: ReportDataAsset[]
  components: ReportComponents
  flows: ReportFlow[]
  threatAnalysis: ReportThreatAnalysis
  countermeasureSummary: ReportCountermeasureSummary
  risks: ReportRisk[]
  compliance: ReportCompliance
  summaryMetrics: ReportSummaryMetrics
  progressChecklist: ReportProgressItem[]
  completionStatus?: ReportCompletionStatus
}
