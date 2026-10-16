/**
 * The CycloneDX 2.0 TM-BOM objects the guest editor reads and writes, in the
 * shape the backend adapter emits (`backend/apps/threat_models/tmbom/`).
 *
 * Every object may carry keys beyond the ones named here; the adapter keeps
 * them as passthrough. A `type`-like field is a spec value or the spec's
 * custom object `{name, description?}`.
 */

export interface CycloneDxCustomType {
  name: string
  description?: string
}

export type CycloneDxTypeValue = string | CycloneDxCustomType

export interface CycloneDxProperty {
  name: string
  value?: string
}

export interface CycloneDxDocument {
  specFormat: 'CycloneDX'
  specVersion: string
  serialNumber?: string
  version?: number
  metadata?: CycloneDxMetadata
  blueprints?: CycloneDxBlueprint[]
  threats?: CycloneDxThreatsSection
  controls?: CycloneDxControl[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxMetadata {
  timestamp?: string
  tools?: { components?: { type: string; name: string; version?: string }[] }
  component?: CycloneDxMetadataComponent
  [key: string]: unknown
}

export interface CycloneDxMetadataComponent {
  type: string
  'bom-ref'?: string
  name: string
  description?: string
  properties?: CycloneDxProperty[]
  parties?: Record<string, unknown>[]
  [key: string]: unknown
}

export interface CycloneDxBlueprint {
  'bom-ref'?: string
  name: string
  description?: string
  modelTypes: CycloneDxTypeValue[]
  scope?: CycloneDxScope
  assets?: CycloneDxAsset[]
  dataStores?: CycloneDxDataStore[]
  dataSets?: CycloneDxDataSet[]
  zones?: CycloneDxZone[]
  boundaries?: CycloneDxBoundary[]
  flows?: CycloneDxFlow[]
  assumptions?: CycloneDxAssumption[]
  visualizations?: CycloneDxVisualization[]
  [key: string]: unknown
}

export interface CycloneDxScope {
  name: string
  description?: string
  excludedComponents?: string[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxAsset {
  'bom-ref': string
  name: string
  type: CycloneDxTypeValue
  description?: string
  zone?: string
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxDataStore {
  'bom-ref': string
  name: string
  type: CycloneDxTypeValue
  description?: string
  vendor?: string
  zone?: string
  dataSets?: string[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxDataProfile {
  'bom-ref'?: string
  name: string
  classification?: CycloneDxTypeValue
  regulations?: string[]
  [key: string]: unknown
}

export interface CycloneDxDataSet {
  'bom-ref': string
  name: string
  description: string
  dataProfiles?: (CycloneDxDataProfile | string)[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxZone {
  'bom-ref': string
  name: string
  type: CycloneDxTypeValue
  description?: string
  parent?: string
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxCrossingRequirements {
  authentication?: CycloneDxTypeValue[]
  authorization?: CycloneDxTypeValue[]
  dataValidation?: boolean
  dataTransformation?: boolean
  logging?: boolean
  monitoring?: boolean
  rateLimit?: string
  protocols?: string[]
}

export interface CycloneDxBoundary {
  'bom-ref': string
  zones: string[]
  type?: CycloneDxTypeValue
  name?: string
  crossingRequirements?: CycloneDxCrossingRequirements
  sessionManagement?: Record<string, unknown>
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxFlow {
  'bom-ref': string
  name: string
  type: CycloneDxTypeValue
  source: string
  destination: string
  description?: string
  encrypted?: boolean
  protocols?: string[]
  authentication?: CycloneDxTypeValue[]
  authorization?: CycloneDxTypeValue[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxAssumption {
  'bom-ref'?: string
  description: string
  validity?: string
  topic?: CycloneDxTypeValue
  [key: string]: unknown
}

export interface CycloneDxAttachment {
  mediaType?: string
  encoding?: 'base64'
  content: string
}

export interface CycloneDxVisualization {
  'bom-ref'?: string
  name: string
  type: { type: string } | CycloneDxCustomType
  attachment?: CycloneDxAttachment
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxThreatsSection {
  threats?: CycloneDxThreat[]
  scenarios?: CycloneDxScenario[]
  trustBoundaries?: CycloneDxTrustBoundary[]
  methodologies?: CycloneDxTypeValue[]
  [key: string]: unknown
}

export interface CycloneDxThreatCategory {
  taxonomy: string
  category: string
}

export interface CycloneDxThreat {
  'bom-ref': string
  name: string
  description?: string
  categories?: CycloneDxThreatCategory[]
  mitigations?: string[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxRiskScore {
  level: string
  score?: number
  methodology?: CycloneDxTypeValue
  [key: string]: unknown
}

export interface CycloneDxScenario {
  'bom-ref': string
  name: string
  threats: string[]
  description?: string
  affectedAssets?: string[]
  riskScore?: CycloneDxRiskScore
  likelihood?: Record<string, unknown>
  impact?: Record<string, unknown>
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}

export interface CycloneDxTrustBoundary {
  'bom-ref': string
  boundary: string
  name?: string
  description?: string
  trustLevel?: string
  threatsAtBoundary?: string[]
  controlsAtBoundary?: string[]
  [key: string]: unknown
}

export interface CycloneDxControl {
  'bom-ref': string
  name: string
  description?: string
  category?: CycloneDxTypeValue
  status?: CycloneDxTypeValue
  appliesTo?: string[]
  properties?: CycloneDxProperty[]
  [key: string]: unknown
}
