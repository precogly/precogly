/**
 * Ratings, risks and risk responses (issues #583/#584, plan section 4.2 and
 * the #31 comment section 2.8).
 *
 * The read shape of a rating is `rating_to_dict` in
 * backend/apps/threats/serializers.py; the write shape is `rating_inputs`,
 * validated by the engines in backend/apps/threats/scoring/.
 */

import type { ImpactCategory, LabeledValue, RiskDomain } from '@/types/domain'

// backend/apps/threats/models.py Rating.Level (CycloneDX riskScore.level)
export type RatingLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'

export const RATING_LEVELS: LabeledValue<RatingLevel>[] = [
  { value: 'info', label: 'Info' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

/** Rank of a level for sorting; higher is worse. */
export const RATING_LEVEL_RANK: Record<RatingLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** Kept for readers that still say "risk level"; the same five values. */
export type RiskLevel = RatingLevel

// backend/apps/threats/models.py Rating.LikelihoodLevel and Rating.ImpactLevel
export type LikelihoodLevel = 'very-low' | 'low' | 'medium' | 'high' | 'very-high' | 'certain'
export type ImpactLevel = 'negligible' | 'low' | 'moderate' | 'major' | 'catastrophic'

// backend/apps/threat_models/models.py ThreatModel.risk_scoring_method choices
export type ScoringMethodKey = 'qualitative-matrix' | 'owasp-risk-rating' | 'fair' | 'mozilla-rra'

/** A rating's methodology: a scoring method, `manual` (level only) or a custom name from an import. */
export type RatingMethodology = ScoringMethodKey | 'manual' | string

export interface RatingFactor {
  name: string
  /** Likelihood factors carry a spec type or a custom `{ name }` object. */
  type?: string | { name: string }
  /** Impact factors carry a spec category or a custom `{ name }` object. */
  category?: string | { name: string }
  score: number
}

export interface RatingAxis {
  level: string
  score: number | null
  factors: RatingFactor[]
  extra: Record<string, unknown>
}

export interface ImpactQuantification {
  financialLoss?: number
  /** ISO 4217 code, for example USD. */
  currency?: string
  financialLossRange?: {
    minimum?: number
    mostLikely?: number
    maximum?: number
  }
}

/** The read shape of a rating (`rating_to_dict`). */
export interface Rating {
  id: number
  methodology: RatingMethodology
  level: RatingLevel
  /** On the method's native scale; null for a level-only rating. */
  score: number | null
  likelihood: RatingAxis | null
  impact: RatingAxis | null
  rationale: string
}

/** The impact section of a rating as the form reads it back (`impact.extra`). */
export function ratingImpactExtra(rating: Rating | null | undefined): {
  categories: ImpactCategory[]
  quantification: ImpactQuantification
} {
  const extra = rating?.impact?.extra ?? {}
  const categories = Array.isArray(extra.categories) ? (extra.categories as ImpactCategory[]) : []
  const quantification =
    extra.quantification && typeof extra.quantification === 'object'
      ? (extra.quantification as ImpactQuantification)
      : {}
  return { categories, quantification }
}

// ---------------------------------------------------------------------------
// rating_inputs: what the form sends. Keys are camelCase here; the API layer
// writes them as snake_case, nested keys included.
// ---------------------------------------------------------------------------

/** The impact section every engine accepts (serializers.validate_impact_extra). */
export interface ImpactExtraInputs {
  impactCategories?: ImpactCategory[]
  impactQuantification?: ImpactQuantification
}

/** backend/apps/threats/scoring/manual.py: a level alone, with rationale. */
export interface LevelOnlyRatingInputs extends ImpactExtraInputs {
  level: RatingLevel
  rationale?: string
}

// backend/apps/threats/scoring/qualitative_matrix.py vocabulary
export type MatrixLikelihood = 'rare' | 'unlikely' | 'possible' | 'likely' | 'certain'
export type MatrixImpact = 'negligible' | 'minor' | 'moderate' | 'major' | 'severe'

export const MATRIX_LIKELIHOODS: LabeledValue<MatrixLikelihood>[] = [
  { value: 'rare', label: 'Rare' },
  { value: 'unlikely', label: 'Unlikely' },
  { value: 'possible', label: 'Possible' },
  { value: 'likely', label: 'Likely' },
  { value: 'certain', label: 'Certain' },
]

export const MATRIX_IMPACTS: LabeledValue<MatrixImpact>[] = [
  { value: 'negligible', label: 'Negligible' },
  { value: 'minor', label: 'Minor' },
  { value: 'moderate', label: 'Moderate' },
  { value: 'major', label: 'Major' },
  { value: 'severe', label: 'Severe' },
]

/** The matrix engine's stored levels back to the form vocabulary (SPEC_TO_LIKELIHOOD, SPEC_TO_IMPACT). */
export const MATRIX_LIKELIHOOD_FROM_LEVEL: Record<string, MatrixLikelihood> = {
  'very-low': 'rare',
  low: 'unlikely',
  medium: 'possible',
  high: 'likely',
  certain: 'certain',
}

export const MATRIX_IMPACT_FROM_LEVEL: Record<string, MatrixImpact> = {
  negligible: 'negligible',
  low: 'minor',
  moderate: 'moderate',
  major: 'major',
  catastrophic: 'severe',
}

export interface QualitativeMatrixRatingInputs extends ImpactExtraInputs {
  likelihood: MatrixLikelihood
  impact: MatrixImpact
  rationale?: string
}

// backend/apps/threats/scoring/owasp_risk_rating.py GROUPS: sixteen factors,
// 0 to 9, in four groups. The group and field keys are camelCase here.
export type OwaspGroupKey = 'threatAgent' | 'vulnerability' | 'technicalImpact' | 'businessImpact'

export type OwaspThreatAgentFactor = 'skillLevel' | 'motive' | 'opportunity' | 'size'
export type OwaspVulnerabilityFactor = 'easeOfDiscovery' | 'easeOfExploit' | 'awareness' | 'intrusionDetection'
export type OwaspTechnicalImpactFactor =
  | 'lossOfConfidentiality'
  | 'lossOfIntegrity'
  | 'lossOfAvailability'
  | 'lossOfAccountability'
export type OwaspBusinessImpactFactor = 'financialDamage' | 'reputationDamage' | 'nonCompliance' | 'privacyViolation'

export interface OwaspRiskRatingInputs extends ImpactExtraInputs {
  threatAgent: Record<OwaspThreatAgentFactor, number>
  vulnerability: Record<OwaspVulnerabilityFactor, number>
  technicalImpact: Record<OwaspTechnicalImpactFactor, number>
  businessImpact: Record<OwaspBusinessImpactFactor, number>
  rationale?: string
}

export const OWASP_GROUPS: { key: OwaspGroupKey; label: string; fields: string[] }[] = [
  {
    key: 'threatAgent',
    label: 'Threat agent factors',
    fields: ['skillLevel', 'motive', 'opportunity', 'size'],
  },
  {
    key: 'vulnerability',
    label: 'Vulnerability factors',
    fields: ['easeOfDiscovery', 'easeOfExploit', 'awareness', 'intrusionDetection'],
  },
  {
    key: 'technicalImpact',
    label: 'Technical impact factors',
    fields: ['lossOfConfidentiality', 'lossOfIntegrity', 'lossOfAvailability', 'lossOfAccountability'],
  },
  {
    key: 'businessImpact',
    label: 'Business impact factors',
    fields: ['financialDamage', 'reputationDamage', 'nonCompliance', 'privacyViolation'],
  },
]

/** What a rating form produces; the backend picks the engine from the keys. */
export type RatingInputs = LevelOnlyRatingInputs | QualitativeMatrixRatingInputs | OwaspRiskRatingInputs

export function isLevelOnlyInputs(inputs: RatingInputs): inputs is LevelOnlyRatingInputs {
  return 'level' in inputs
}

export function isMatrixInputs(inputs: RatingInputs): inputs is QualitativeMatrixRatingInputs {
  return 'likelihood' in inputs && 'impact' in inputs
}

export function isOwaspInputs(inputs: RatingInputs): inputs is OwaspRiskRatingInputs {
  return 'threatAgent' in inputs
}

// ---------------------------------------------------------------------------
// GET /api/scoring-methods/ (backend/apps/threats/scoring/registry.py)
// ---------------------------------------------------------------------------

export interface ScoringFieldSchema {
  type: 'enum' | 'integer' | 'number' | 'text' | 'group'
  values?: string[]
  /** For enums: one label per value. For integers: one label per step (nulls between OWASP's named values). */
  labels?: (string | null)[]
  min?: number
  max?: number
  label?: string
  required: boolean
  /** For `group` fields: the fields inside the group, keyed camelCase. */
  fields?: Record<string, ScoringFieldSchema>
}

export interface ScoringMethod {
  key: ScoringMethodKey
  label: string
  description: string
  /** Keys are camelCase after the API layer's conversion (for example `threatAgent.skillLevel`). */
  inputSchema: Record<string, ScoringFieldSchema>
  /** Shown next to the score, for example "25" or "9"; empty when no engine. */
  scoreScale: string
  available: boolean
}

// ---------------------------------------------------------------------------
// Risks (backend/apps/threats/serializers.py RiskListSerializer and
// RiskDetailSerializer)
// ---------------------------------------------------------------------------

// backend/apps/threats/models.py Risk.Status (CycloneDX risk.status)
export type RiskStatus = 'identified' | 'assessed' | 'mitigated' | 'accepted' | 'transferred' | 'retired'

export const RISK_STATUSES: LabeledValue<RiskStatus>[] = [
  { value: 'identified', label: 'Identified' },
  { value: 'assessed', label: 'Assessed' },
  { value: 'mitigated', label: 'Mitigated' },
  { value: 'accepted', label: 'Accepted' },
  { value: 'transferred', label: 'Transferred' },
  { value: 'retired', label: 'Retired' },
]

/** Derived from the linked threats (services.derive_risk_status); read-only. */
export type RiskExposure = 'exposed' | 'addressable' | 'mitigated'

export interface RiskThreatEntry {
  riskThreatId: number
  threatId: number
  displayNumber: string
  threatName: string | null
  status: string
  triageStatus: string
  wholeSystem: boolean
  rating: Rating | null
  targets: RiskThreatTarget[]
}

export interface RiskThreatTarget {
  type: 'component' | 'flow' | 'zone' | 'boundary'
  id: number
  name: string | null
  blueprintId: number
}

export interface BusinessObjectiveRef {
  id: number
  name: string
}

export interface Risk {
  id: number
  name: string
  description: string
  scoringMethod: ScoringMethodKey
  inherent: Rating | null
  residual: Rating | null
  target: Rating | null
  status: RiskStatus
  exposure: RiskExposure
  /** Detail only. */
  statement?: string
  /** Detail only. */
  domains?: RiskDomain[]
  /** Detail only. */
  businessObjectiveIds?: number[]
  /** Detail only. */
  businessObjectives?: BusinessObjectiveRef[]
  /** Detail only. */
  responses?: RiskResponse[]
  /** List only. */
  threatCount?: number
  /** Detail only. */
  threats?: RiskThreatEntry[]
  owner: number | null
  ownerEmail: string | null
  assignedTo: number | null
  assignedToEmail: string | null
  /** Detail only. */
  formatMetadata?: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

// backend/apps/threats/models.py RiskResponse choices
export type RiskResponseStrategy = 'avoid' | 'reduce' | 'transfer' | 'accept'
export type RiskResponseStatus = 'planned' | 'in_progress' | 'implemented' | 'verified'
export type RiskResponseCost = 'trivial' | 'low' | 'medium' | 'high' | 'extreme'
export type RiskResponsePriority = 'none' | 'low' | 'medium' | 'high' | 'critical'

export const RISK_RESPONSE_STRATEGIES: LabeledValue<RiskResponseStrategy>[] = [
  { value: 'reduce', label: 'Reduce' },
  { value: 'avoid', label: 'Avoid' },
  { value: 'transfer', label: 'Transfer' },
  { value: 'accept', label: 'Accept' },
]

export const RISK_RESPONSE_STATUSES: LabeledValue<RiskResponseStatus>[] = [
  { value: 'planned', label: 'Planned' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'implemented', label: 'Implemented' },
  { value: 'verified', label: 'Verified' },
]

export const RISK_RESPONSE_COSTS: LabeledValue<RiskResponseCost>[] = [
  { value: 'trivial', label: 'Trivial' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'extreme', label: 'Extreme' },
]

export const RISK_RESPONSE_PRIORITIES: LabeledValue<RiskResponsePriority>[] = [
  { value: 'none', label: 'None' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

export interface RiskResponseCountermeasureRef {
  id: number
  displayNumber: string
  countermeasureName: string
  status: string
}

/** backend/apps/threats/serializers.py RiskResponseSerializer */
export interface RiskResponse {
  id: number
  risk: number
  strategy: RiskResponseStrategy
  description: string
  status: RiskResponseStatus
  /** 0 to 1, or null. */
  effectiveness: number | null
  cost: RiskResponseCost | ''
  priority: RiskResponsePriority | ''
  owner: number | null
  ownerEmail: string | null
  targetDate: string | null
  countermeasureIds?: number[]
  countermeasures: RiskResponseCountermeasureRef[]
  formatMetadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface CreateRiskResponseInput {
  strategy: RiskResponseStrategy
  description?: string
  status?: RiskResponseStatus
  effectiveness?: number | null
  cost?: RiskResponseCost | ''
  priority?: RiskResponsePriority | ''
  owner?: number | null
  targetDate?: string | null
  countermeasureIds?: number[]
}

export type UpdateRiskResponseInput = Partial<CreateRiskResponseInput>

export interface CreateRiskInput {
  name: string
  description?: string
  /** Required on create: a level alone, or the model's method's inputs. */
  ratingInputs: RatingInputs
  status?: RiskStatus
  statement?: string
  domains?: RiskDomain[]
  businessObjectiveIds?: number[]
  owner?: number | null
  assignedTo?: number | null
  threatIds?: number[]
}

export interface UpdateRiskInput {
  name?: string
  description?: string
  ratingInputs?: RatingInputs
  status?: RiskStatus
  statement?: string
  domains?: RiskDomain[]
  businessObjectiveIds?: number[]
  owner?: number | null
  assignedTo?: number | null
}

export interface AddRemoveThreatsInput {
  threatIds: number[]
}

export interface BulkUpdateRisksInput {
  riskIds: number[]
  status?: RiskStatus
  owner?: number | null
}

/** backend/apps/threats/serializers.py CountermeasureCommentSerializer */
export interface CountermeasureComment {
  id: number
  author: number | null
  authorEmail: string | null
  countermeasure: number
  body: string
  changeSummary: string
  createdAt: string
  updatedAt: string
}
