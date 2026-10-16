import type {
  AssumptionTopic,
  AssumptionValidity,
  BusinessObjectiveCriticality,
  Criticality,
  LifecyclePhase,
  ModelType,
  RelationType,
  SystemType,
} from '@/types/domain'
import type { ScoringMethodKey } from '@/types/risk'

export interface ReferenceImage {
  id: number
  threatModel: number
  image: string
  imageUrl: string
  filename: string
  description: string
  displayOrder: number
  uploadedBy: number | null
  uploadedByEmail: string | null
  createdAt: string
}

/** backend/apps/threat_models/serializers.py BlueprintSerializer */
export interface Blueprint {
  id: number
  threatModel: number
  name: string
  description: string
  modelTypes: ModelType[]
  scopeDescription: string
  displayOrder: number
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface CreateBlueprintInput {
  name: string
  description?: string
  modelTypes?: ModelType[]
  scopeDescription?: string
  displayOrder?: number
}

export type UpdateBlueprintInput = Partial<CreateBlueprintInput>

/** GET /threat-models/{id}/blueprints/{blueprintId}/delete_preview/ */
export interface BlueprintDeletePreview {
  blueprint: { id: number; name: string }
  isLast: boolean
  components: number
  flows: number
  zones: number
  boundaries: number
  diagrams: number
  dataAssets: number
  outOfScopeItems: number
  assumptions: number
  /** Scenarios whose only targets sit in this blueprint. */
  threatsDeleted: number
  /** Scenarios that also target rows elsewhere: they stay and lose these targets. */
  threatsLosingTargets: number
}

/** backend/apps/threat_models/serializers.py AssumptionSerializer (rows on a blueprint, plan 4.8) */
export interface Assumption {
  id: number
  blueprint: number
  description: string
  topic: AssumptionTopic | ''
  validity: AssumptionValidity
  impact: string
  owner: number | null
  ownerEmail: string | null
  ownerName: string
  validationMethod: string
  validationDate: string | null
  componentIds: number[]
  components: Array<{ id: number; name: string }>
  displayOrder: number
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface CreateAssumptionInput {
  /** Defaults to the model's first blueprint. */
  blueprint?: number
  description: string
  topic?: AssumptionTopic | ''
  validity?: AssumptionValidity
  impact?: string
  owner?: number | null
  ownerName?: string
  validationMethod?: string
  validationDate?: string | null
  /** Components of the same blueprint. */
  componentIds?: number[]
  displayOrder?: number
}

export type UpdateAssumptionInput = Partial<CreateAssumptionInput>

/** backend/apps/threat_models/serializers.py BusinessObjectiveSerializer */
export interface BusinessObjective {
  id: number
  threatModel: number
  name: string
  description: string
  criticality: BusinessObjectiveCriticality | ''
  owner: number | null
  ownerEmail: string | null
  ownerName: string
  displayOrder: number
  threatCount: number
  riskCount: number
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface CreateBusinessObjectiveInput {
  name: string
  description?: string
  criticality?: BusinessObjectiveCriticality | ''
  owner?: number | null
  ownerName?: string
  displayOrder?: number
}

export type UpdateBusinessObjectiveInput = Partial<CreateBusinessObjectiveInput>

/** backend/apps/threat_models/review.py review_state: `none`, `approved` or `changed`. Overdue review is the separate `reviewDue` flag. */
export type ApprovalState = 'none' | 'approved' | 'changed'

/** GET /threat-models/{id}/review/ and the three review actions */
export interface ReviewState {
  approvalState: ApprovalState
  /** True once validUntil has passed, whatever the approval state is. */
  reviewDue: boolean
  reviewer: number | null
  reviewerEmail: string | null
  reviewedAt: string | null
  approver: number | null
  approverEmail: string | null
  approvedAt: string | null
  currentDigest: string
  approvalDigest: string | null
  validFrom: string | null
  validUntil: string | null
  reviewFrequency: string
  lifecyclePhase: LifecyclePhase | ''
  /** The review block of an imported document, shown as history (D18). */
  sourceDocumentReview: Record<string, unknown> | null
}

/**
 * A step of a main flow or an alternative flow (backend/apps/threat_models/flow_data.py).
 * The backend renumbers steps 1..n on save; `actor` is an imported ref, shown
 * read-only and kept.
 */
export interface FlowStep {
  number?: number
  description: string
  actor?: string
}

export interface AlternativeFlow {
  name: string
  condition: string
  description?: string
  steps?: FlowStep[]
}

export interface UseCaseException {
  name: string
  condition: string
  description?: string
  /** One string in the spec, not steps. */
  handling?: string
}

/** Use case `flowData`: every list is optional; unknown keys are kept by the backend. */
export interface UseCaseFlowData {
  preconditions?: string[]
  postconditions?: string[]
  successCriteria?: string[]
  notes?: string[]
  mainFlow?: FlowStep[]
  alternativeFlows?: AlternativeFlow[]
  exceptions?: UseCaseException[]
  [key: string]: unknown
}

/** Abuse case `flowData`. */
export interface AbuseCaseFlowData {
  preconditions?: string[]
  mainFlow?: FlowStep[]
  detectionOpportunities?: string[]
  [key: string]: unknown
}

/** A component a use case or abuse case links to. */
export interface LinkedComponent {
  id: number
  name: string
  blueprintId: number
}

/** A flow a use case or abuse case links to; shown as "Source to Destination (name)". */
export interface LinkedFlow {
  id: number
  name: string
  sourceName: string
  destinationName: string
  blueprintId: number
}

/** backend/apps/threat_models/serializers.py UseCaseSerializer */
export interface UseCase {
  id: number
  name: string
  description: string
  flowData: UseCaseFlowData | null
  displayOrder: number
  components: LinkedComponent[]
  flows: LinkedFlow[]
  businessObjectives: { id: number; name: string }[]
  abuseCaseCount: number
  createdAt: string
  updatedAt: string
}

/** Link fields replace what they name; `[]` clears; an omitted field keeps the links. */
export interface UseCaseInput {
  name?: string
  description?: string
  flowData?: UseCaseFlowData
  displayOrder?: number
  componentIds?: number[]
  flowIds?: number[]
  businessObjectiveIds?: number[]
}

/**
 * A library threat an imported abuse case realizes that no threat of the model
 * links to it yet. Shown as "Realizes library threat X, not linked to a threat
 * in this model" with a link action. `libraryThreatId` for a library row,
 * `ref` for a threat that is no library row here.
 */
export interface UnlinkedRealizes {
  libraryThreatId?: number
  ref?: string
  name: string
}

/** backend/apps/threat_models/serializers.py AbuseCaseSerializer */
export interface AbuseCase {
  id: number
  name: string
  description: string
  flowData: AbuseCaseFlowData | null
  displayOrder: number
  abuser: { id: number; name: string } | null
  useCases: { id: number; name: string }[]
  components: LinkedComponent[]
  flows: LinkedFlow[]
  threats: { id: number; number: number; displayNumber: string; name: string }[]
  unlinkedRealizes: UnlinkedRealizes[]
  /** Controls an imported abuse case names; read-only. */
  mitigations: { id: number; displayNumber: string; name: string }[]
  createdAt: string
  updatedAt: string
}

export interface AbuseCaseInput {
  name?: string
  description?: string
  flowData?: AbuseCaseFlowData
  displayOrder?: number
  abuserId?: number | null
  useCaseIds?: number[]
  componentIds?: number[]
  flowIds?: number[]
  threatIds?: number[]
}

/** One relationship as the model sees it (threat_models/relationships.py relationship_payload). */
export interface RelatedModel {
  id: number
  sourceModelId: number
  targetModelId: number
  relationType: RelationType
  /** `outgoing` when this model is the source, `incoming` when it is the target. */
  direction: 'outgoing' | 'incoming'
  /** The other end. */
  model: { id: number; name: string }
}

export interface ThreatModelFrameworkRef {
  id: number
  name: string
  version?: string
}

export interface ConnectedPack {
  id: number
  name: string
  slug: string
  version: string
  packType: string
}

/**
 * backend/apps/threat_models/serializers.py ThreatModelSerializer (detail)
 * and ThreatModelListSerializer. Fields the list leaves out are optional.
 */
export interface ThreatModel {
  id: string
  name: string
  description: string
  criticality?: Criticality
  frameworks?: ThreatModelFrameworkRef[]
  owner?: string
  organization?: number
  organizationName?: string
  owningTeam?: number | null
  owningTeamName?: string | null
  businessUnitName?: string | null
  /** Spec methodology values or custom names; default ["STRIDE"]. */
  methodologies?: string[]
  lifecyclePhase?: LifecyclePhase | ''
  validFrom?: string | null
  validUntil?: string | null
  /** ISO 8601 duration, for example P3M. */
  reviewFrequency?: string
  approvedAt?: string | null
  primarySystem?: number | null
  primarySystemName?: string | null
  serialNumber?: string
  version?: number
  /** Detail only. */
  blueprints?: Blueprint[]
  /** List only. */
  blueprintCount?: number
  packIds?: number[]
  connectedPacks?: ConnectedPack[]
  /** Ids of the models this one points at, whatever the relation type. */
  referencedModelIds?: string[]
  /** Every relationship the model takes part in, with type and direction (plan J15). */
  relatedModels?: RelatedModel[]
  riskScoringMethod?: ScoringMethodKey
  referenceImages?: ReferenceImage[]
  formatMetadata?: Record<string, unknown>
  createdAt?: string
  updatedAt?: string
  createdBy?: string
  createdByEmail?: string
  workspaceData?: Record<string, unknown>
  dfds?: Array<{
    id: string
    name: string
    diagramType?: string
    blueprint?: number
    isPrimary?: boolean
    updatedAt?: string
  }>
}

/** backend/apps/threat_models/serializers.py ThreatModelCreateSerializer */
export interface CreateThreatModelInput {
  name: string
  description?: string
  organization?: number
  owningTeam?: number
  criticality?: Criticality
  frameworkIds?: number[]
  primarySystem?: number | null
  referencedModelIds?: number[]
  methodologies?: string[]
  riskScoringMethod?: ScoringMethodKey
}

export interface DashboardRiskStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info?: number
  exposed: number
  mitigated: number
}

export interface DashboardStats {
  total: number
  risks?: DashboardRiskStats
}

export type SystemLifecycleState = 'development' | 'production' | 'decommissioned'

/** backend/apps/systems/serializers.py OrgsystemSerializer and OrgsystemListSerializer */
export interface System {
  id: number
  name: string
  type: SystemType
  owner: string
  /** Alias of lifecycleState kept by the serializer. */
  environment: string
  description?: string
  criticality?: Criticality
  lifecycleState?: SystemLifecycleState
  organization?: number
  /** Threat models whose primary system this is (plan J1). */
  primaryModelCount?: number
  /** System assets (components of kind system) linked to it. */
  linkedComponentCount?: number
  /** Detail only. */
  primaryModels?: Array<{ id: number; name: string }>
  formatMetadata?: Record<string, unknown>
  createdAt?: string
  updatedAt?: string
}

export interface CreateSystemInput {
  name: string
  description?: string
  owner?: string
  criticality?: Criticality
  lifecycleState?: SystemLifecycleState
}

export type UpdateSystemInput = Partial<CreateSystemInput>

/** The 409 body when deleting a system that is some model's primary system. */
export interface SystemDeleteConflict {
  error: string
  models: Array<{ id: number; name: string }>
}
