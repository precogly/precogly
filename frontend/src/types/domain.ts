/**
 * Shared domain types - single source of truth for enum values and common types.
 * These types match backend TextChoices exactly.
 */

// STRIDE Categories - kebab-case IDs matching TaxonomyEntry.external_id
export type STRIDECategory =
  | 'spoofing'
  | 'tampering'
  | 'repudiation'
  | 'information-disclosure'
  | 'denial-of-service'
  | 'elevation-of-privilege'

export const STRIDE_CATEGORIES: { value: STRIDECategory; label: string }[] = [
  { value: 'spoofing', label: 'Spoofing' },
  { value: 'tampering', label: 'Tampering' },
  { value: 'repudiation', label: 'Repudiation' },
  { value: 'information-disclosure', label: 'Information Disclosure' },
  { value: 'denial-of-service', label: 'Denial of Service' },
  { value: 'elevation-of-privilege', label: 'Elevation of Privilege' },
]

// STRIDE display configuration with colors
export const STRIDE_CONFIG: Record<
  STRIDECategory,
  { label: string; shortLabel: string; description: string; color: string }
> = {
  spoofing: {
    label: 'Spoofing',
    shortLabel: 'S',
    description: 'Pretending to be something or someone else',
    color: '#ef4444', // red
  },
  tampering: {
    label: 'Tampering',
    shortLabel: 'T',
    description: 'Modifying data or code without authorization',
    color: '#f97316', // orange
  },
  repudiation: {
    label: 'Repudiation',
    shortLabel: 'R',
    description: 'Denying having performed an action',
    color: '#eab308', // yellow
  },
  'information-disclosure': {
    label: 'Information Disclosure',
    shortLabel: 'I',
    description: 'Exposing information to unauthorized parties',
    color: '#22c55e', // green
  },
  'denial-of-service': {
    label: 'Denial of Service',
    shortLabel: 'D',
    description: 'Making a system unavailable or degraded',
    color: '#3b82f6', // blue
  },
  'elevation-of-privilege': {
    label: 'Elevation of Privilege',
    shortLabel: 'E',
    description: 'Gaining unauthorized capabilities or access',
    color: '#8b5cf6', // purple
  },
}

// Taxonomy entry from the unified taxonomy system
// id and taxonomyName are optional to support snapshot entries (after pack unimport)
export interface TaxonomyEntry {
  id?: number
  taxonomySlug: string
  taxonomyName?: string
  externalId: string
  title: string
  referenceUrl?: string
  source?: 'library' | 'instance' | 'snapshot'
}

// Lightweight subset used by TaxonomyBadges and helper functions (e.g. pack previews)
export type TaxonomyBadgeEntry = Pick<TaxonomyEntry, 'taxonomySlug' | 'externalId' | 'title'> & {
  referenceUrl?: string
}

/**
 * Extract the first STRIDE category from taxonomy entries.
 * Returns the externalId of the first entry where taxonomySlug === 'stride'.
 */
export function getStrideFromTaxonomy(entries?: TaxonomyEntry[]): STRIDECategory | undefined {
  if (!entries) return undefined
  const strideEntry = entries.find((e) => e.taxonomySlug === 'stride')
  return strideEntry?.externalId as STRIDECategory | undefined
}

// Taxonomy-agnostic color configuration per taxonomy slug
export const TAXONOMY_COLOR_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  capec: { bg: 'bg-cyan-50', text: 'text-cyan-700', border: 'border-cyan-200' },
  cwe: { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200' },
  'mitre-attack': { bg: 'bg-indigo-50', text: 'text-indigo-700', border: 'border-indigo-200' },
}

const TAXONOMY_COLOR_FALLBACK = { bg: 'bg-slate-50', text: 'text-slate-600', border: 'border-slate-200' }

/**
 * Returns a human-readable display label for a taxonomy entry.
 * - STRIDE → human-readable label (e.g., "Tampering")
 * - CAPEC → "CAPEC-{externalId}" (e.g., "CAPEC-88")
 * - CWE → externalId as-is (e.g., "CWE-78")
 * - ATT&CK → externalId as-is (e.g., "T1190")
 * - Unknown → externalId or title
 */
export function formatTaxonomyEntryLabel(entry: TaxonomyBadgeEntry): string {
  if (entry.taxonomySlug === 'stride') {
    const strideConfig = STRIDE_CONFIG[entry.externalId as STRIDECategory]
    return strideConfig?.label ?? entry.externalId
  }
  if (entry.taxonomySlug === 'capec') {
    return `CAPEC-${entry.externalId}`
  }
  // CWE and ATT&CK externalIds already include their prefix
  if (entry.taxonomySlug === 'cwe' || entry.taxonomySlug === 'mitre-attack') {
    return entry.externalId
  }
  return entry.externalId || entry.title
}

/**
 * Returns the hex color string for a taxonomy entry.
 * STRIDE entries use per-category colors; others return a neutral gray.
 */
export function getTaxonomyEntryColor(entry: TaxonomyBadgeEntry): string {
  if (entry.taxonomySlug === 'stride') {
    const strideConfig = STRIDE_CONFIG[entry.externalId as STRIDECategory]
    return strideConfig?.color ?? '#64748b'
  }
  return '#64748b'
}

/**
 * Returns the Tailwind background class string for a taxonomy entry.
 * Returns null for STRIDE (uses inline style instead).
 */
export function getTaxonomyEntryBgClass(entry: TaxonomyBadgeEntry): string | null {
  if (entry.taxonomySlug === 'stride') {
    return null
  }
  const config = TAXONOMY_COLOR_CONFIG[entry.taxonomySlug] ?? TAXONOMY_COLOR_FALLBACK
  return `${config.bg} ${config.text} ${config.border}`
}

// Installation Status - matches backend OrganizationPackInstallation.Status
export type InstallationStatus = 'installed' | 'pendingUpdate' | 'failed'

// Criticality levels
export type Criticality = 'low' | 'medium' | 'high' | 'critical'

// System types
export type SystemType = 'system' | 'process'

// Zone color options for the color picker
export const ZONE_COLOR_OPTIONS = [
  { label: 'Red', borderColor: '#ef4444', color: 'rgba(239, 68, 68, 0.1)' },
  { label: 'Orange', borderColor: '#f97316', color: 'rgba(249, 115, 22, 0.1)' },
  { label: 'Amber', borderColor: '#f59e0b', color: 'rgba(245, 158, 11, 0.1)' },
  { label: 'Green', borderColor: '#22c55e', color: 'rgba(34, 197, 94, 0.1)' },
  { label: 'Teal', borderColor: '#14b8a6', color: 'rgba(20, 184, 166, 0.1)' },
  { label: 'Blue', borderColor: '#3b82f6', color: 'rgba(59, 130, 246, 0.1)' },
  { label: 'Purple', borderColor: '#8b5cf6', color: 'rgba(139, 92, 246, 0.1)' },
  { label: 'Pink', borderColor: '#ec4899', color: 'rgba(236, 72, 153, 0.1)' },
] as const

/**
 * Get the background + border color config for a zone, given its stored borderColor.
 * Falls back to green when unset, matching the picker's default.
 */
export function getZoneColorConfig(zoneColor?: string): { color: string; borderColor: string } {
  if (zoneColor) {
    const option = ZONE_COLOR_OPTIONS.find(o => o.borderColor === zoneColor)
    if (option) return { color: option.color, borderColor: option.borderColor }
  }
  return { color: 'rgba(34, 197, 94, 0.1)', borderColor: '#22c55e' }
}

// Trust Zone Preset Names - Conceptual zone names for the Name dropdown
export type TrustZonePresetName = 'internal' | 'external' | 'dmz' | 'partner'

export const TRUST_ZONE_PRESET_NAMES: { value: TrustZonePresetName; label: string; description: string }[] = [
  { value: 'internal', label: 'Internal', description: 'Trusted internal network or zone' },
  { value: 'external', label: 'External', description: 'Untrusted external network (internet-facing)' },
  { value: 'dmz', label: 'DMZ', description: 'Demilitarized zone between trusted and untrusted networks' },
  { value: 'partner', label: 'Partner Network', description: 'Semi-trusted partner or third-party network' },
]

// ---------------------------------------------------------------------------
// CycloneDX TM-BOM value lists, mirrored from the backend (issues #583/#584).
// Each list names the backend file it copies. The backend is the source of
// truth; change it there first.
// ---------------------------------------------------------------------------

export interface LabeledValue<T extends string> {
  value: T
  label: string
}

// backend/apps/systems/crossing.py ZONE_TYPES
export type ZoneType =
  | 'availability'
  | 'compliance'
  | 'data'
  | 'deployment'
  | 'functional'
  | 'geographic'
  | 'logical'
  | 'network'
  | 'organizational'
  | 'physical'
  | 'process'
  | 'tenant'
  | 'trust'

export const ZONE_TYPES: LabeledValue<ZoneType>[] = [
  { value: 'trust', label: 'Trust zone' },
  { value: 'network', label: 'Network zone' },
  { value: 'availability', label: 'Availability zone' },
  { value: 'compliance', label: 'Compliance zone' },
  { value: 'data', label: 'Data zone' },
  { value: 'deployment', label: 'Deployment zone' },
  { value: 'functional', label: 'Functional zone' },
  { value: 'geographic', label: 'Geographic zone' },
  { value: 'logical', label: 'Logical zone' },
  { value: 'organizational', label: 'Organizational zone' },
  { value: 'physical', label: 'Physical zone' },
  { value: 'process', label: 'Process zone' },
  { value: 'tenant', label: 'Tenant zone' },
]
export const DEFAULT_ZONE_TYPE: ZoneType = 'trust'
/** Zone types that carry a trust level (plan 11.11: trust and network zones). */
export const ZONE_TYPES_WITH_TRUST_LEVEL: ZoneType[] = ['trust', 'network']

// backend/apps/systems/crossing.py BOUNDARY_TYPES
export type BoundaryType =
  | 'data'
  | 'functional'
  | 'network'
  | 'organizational'
  | 'physical'
  | 'process'
  | 'trust'

export const BOUNDARY_TYPES: LabeledValue<BoundaryType>[] = [
  { value: 'trust', label: 'Trust boundary' },
  { value: 'network', label: 'Network boundary' },
  { value: 'data', label: 'Data boundary' },
  { value: 'functional', label: 'Functional boundary' },
  { value: 'organizational', label: 'Organizational boundary' },
  { value: 'physical', label: 'Physical boundary' },
  { value: 'process', label: 'Process boundary' },
]
export const DEFAULT_BOUNDARY_TYPE: BoundaryType = 'trust'

// backend/apps/systems/crossing.py FLOW_TYPES and DATA_LIKE_FLOW_TYPES
export type FlowType =
  | 'control'
  | 'data'
  | 'energy'
  | 'event'
  | 'financial'
  | 'message'
  | 'physical'
  | 'process'
  | 'signal'

export const FLOW_TYPES: LabeledValue<FlowType>[] = [
  { value: 'data', label: 'Data flow' },
  { value: 'message', label: 'Message flow' },
  { value: 'event', label: 'Event flow' },
  { value: 'control', label: 'Control flow' },
  { value: 'process', label: 'Process flow' },
  { value: 'signal', label: 'Signal flow' },
  { value: 'financial', label: 'Financial flow' },
  { value: 'energy', label: 'Energy flow' },
  { value: 'physical', label: 'Physical flow' },
]
export const DEFAULT_FLOW_TYPE: FlowType = 'data'
/** Flow types that carry protocol, port and encryption (plan 11.11). */
export const DATA_LIKE_FLOW_TYPES: FlowType[] = ['data', 'message', 'event']

export function isDataLikeFlowType(flowType: FlowType): boolean {
  return DATA_LIKE_FLOW_TYPES.includes(flowType)
}

// backend/apps/systems/crossing.py ASSET_TYPES (the spec asset types; a
// component's "kind"). CATEGORY_TO_KIND gives the default per DFD category.
export type ComponentKind =
  | 'actor'
  | 'agent'
  | 'api'
  | 'broker'
  | 'cache'
  | 'component'
  | 'container'
  | 'data'
  | 'data-store'
  | 'device'
  | 'endpoint'
  | 'function'
  | 'gateway'
  | 'infrastructure'
  | 'interface'
  | 'model'
  | 'module'
  | 'network'
  | 'process'
  | 'queue'
  | 'resource'
  | 'service'
  | 'stream'
  | 'subsystem'
  | 'system'
  | 'tool'

export const COMPONENT_KINDS: LabeledValue<ComponentKind>[] = [
  { value: 'actor', label: 'Actor' },
  { value: 'agent', label: 'Agent' },
  { value: 'api', label: 'API' },
  { value: 'broker', label: 'Broker' },
  { value: 'cache', label: 'Cache' },
  { value: 'component', label: 'Component' },
  { value: 'container', label: 'Container' },
  { value: 'data', label: 'Data' },
  { value: 'data-store', label: 'Data store' },
  { value: 'device', label: 'Device' },
  { value: 'endpoint', label: 'Endpoint' },
  { value: 'function', label: 'Function' },
  { value: 'gateway', label: 'Gateway' },
  { value: 'infrastructure', label: 'Infrastructure' },
  { value: 'interface', label: 'Interface' },
  { value: 'model', label: 'Model' },
  { value: 'module', label: 'Module' },
  { value: 'network', label: 'Network' },
  { value: 'process', label: 'Process' },
  { value: 'queue', label: 'Queue' },
  { value: 'resource', label: 'Resource' },
  { value: 'service', label: 'Service' },
  { value: 'stream', label: 'Stream' },
  { value: 'subsystem', label: 'Subsystem' },
  { value: 'system', label: 'System' },
  { value: 'tool', label: 'Tool' },
]
export const DEFAULT_COMPONENT_KIND: ComponentKind = 'component'

/** backend/apps/systems/crossing.py CATEGORY_TO_KIND, by backend category. */
export const CATEGORY_TO_KIND: Record<string, ComponentKind> = {
  process: 'process',
  datastore: 'data-store',
  external_human_actor: 'actor',
  external_system_actor: 'actor',
}

// backend/apps/systems/crossing.py AUTHENTICATION_TYPES plus UNSPECIFIED (our
// own placeholder: authenticated, method not recorded, I9).
export type AuthenticationType =
  | 'api-key'
  | 'basic'
  | 'bearer'
  | 'biometric'
  | 'certificate'
  | 'digest'
  | 'eap'
  | 'fido2'
  | 'form'
  | 'hmac'
  | 'jwt'
  | 'kerberos'
  | 'ldap'
  | 'magic-link'
  | 'mtls'
  | 'none'
  | 'ntlm'
  | 'oauth1'
  | 'oauth2'
  | 'oidc'
  | 'pin'
  | 'psk'
  | 'push'
  | 'radius'
  | 'saml'
  | 'scram'
  | 'session-cookie'
  | 'ssh'
  | 'totp'
  | 'unspecified'

export const UNSPECIFIED_AUTHENTICATION: AuthenticationType = 'unspecified'
export const NO_AUTHENTICATION: AuthenticationType = 'none'

/** The spec list with the common methods first, as the pickers show it. */
export const AUTHENTICATION_TYPES: LabeledValue<AuthenticationType>[] = [
  { value: 'none', label: 'None' },
  { value: 'unspecified', label: 'Method not specified' },
  { value: 'oauth2', label: 'OAuth 2.0' },
  { value: 'oidc', label: 'OpenID Connect' },
  { value: 'saml', label: 'SAML' },
  { value: 'jwt', label: 'JWT' },
  { value: 'bearer', label: 'Bearer token' },
  { value: 'api-key', label: 'API key' },
  { value: 'session-cookie', label: 'Session cookie' },
  { value: 'form', label: 'Form login' },
  { value: 'basic', label: 'HTTP basic' },
  { value: 'mtls', label: 'Mutual TLS' },
  { value: 'certificate', label: 'Certificate' },
  { value: 'totp', label: 'TOTP' },
  { value: 'fido2', label: 'FIDO2' },
  { value: 'biometric', label: 'Biometric' },
  { value: 'push', label: 'Push notification' },
  { value: 'pin', label: 'PIN' },
  { value: 'magic-link', label: 'Magic link' },
  { value: 'kerberos', label: 'Kerberos' },
  { value: 'ldap', label: 'LDAP' },
  { value: 'ntlm', label: 'NTLM' },
  { value: 'radius', label: 'RADIUS' },
  { value: 'eap', label: 'EAP' },
  { value: 'digest', label: 'HTTP digest' },
  { value: 'hmac', label: 'HMAC' },
  { value: 'oauth1', label: 'OAuth 1.0' },
  { value: 'psk', label: 'Pre-shared key' },
  { value: 'scram', label: 'SCRAM' },
  { value: 'ssh', label: 'SSH' },
]

// backend/apps/systems/crossing.py AUTHORIZATION_TYPES
export type AuthorizationType =
  | 'abac'
  | 'acl'
  | 'capability'
  | 'dac'
  | 'mac'
  | 'none'
  | 'pbac'
  | 'radac'
  | 'rbac'
  | 'rebac'

export const AUTHORIZATION_TYPES: LabeledValue<AuthorizationType>[] = [
  { value: 'none', label: 'None' },
  { value: 'rbac', label: 'RBAC' },
  { value: 'abac', label: 'ABAC' },
  { value: 'acl', label: 'ACL' },
  { value: 'mac', label: 'MAC' },
  { value: 'dac', label: 'DAC' },
  { value: 'pbac', label: 'PBAC' },
  { value: 'rebac', label: 'ReBAC' },
  { value: 'radac', label: 'RAdAC' },
  { value: 'capability', label: 'Capability' },
]

// backend/apps/threats/serializers.py RISK_DOMAINS
export type RiskDomain =
  | 'security'
  | 'privacy'
  | 'operational'
  | 'financial'
  | 'compliance'
  | 'strategic'
  | 'reputational'
  | 'safety'
  | 'environmental'
  | 'supply-chain'
  | 'technical'
  | 'project'
  | 'ethical'
  | 'societal'
  | 'human-rights'
  | 'health'
  | 'legal'

export const RISK_DOMAINS: LabeledValue<RiskDomain>[] = [
  { value: 'security', label: 'Security' },
  { value: 'privacy', label: 'Privacy' },
  { value: 'safety', label: 'Safety' },
  { value: 'operational', label: 'Operational' },
  { value: 'financial', label: 'Financial' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'legal', label: 'Legal' },
  { value: 'strategic', label: 'Strategic' },
  { value: 'reputational', label: 'Reputational' },
  { value: 'environmental', label: 'Environmental' },
  { value: 'supply-chain', label: 'Supply chain' },
  { value: 'technical', label: 'Technical' },
  { value: 'project', label: 'Project' },
  { value: 'ethical', label: 'Ethical' },
  { value: 'societal', label: 'Societal' },
  { value: 'human-rights', label: 'Human rights' },
  { value: 'health', label: 'Health' },
]

// backend/apps/threats/serializers.py IMPACT_CATEGORIES
export type ImpactCategory =
  | 'confidentiality'
  | 'integrity'
  | 'availability'
  | 'financial'
  | 'reputation'
  | 'regulatory'
  | 'safety'
  | 'privacy'
  | 'operational'
  | 'strategic'
  | 'bias'
  | 'discrimination'
  | 'fairness'
  | 'human-rights'
  | 'environmental'
  | 'societal'
  | 'psychological'
  | 'physical'
  | 'health'

export const IMPACT_CATEGORIES: LabeledValue<ImpactCategory>[] = [
  { value: 'confidentiality', label: 'Confidentiality' },
  { value: 'integrity', label: 'Integrity' },
  { value: 'availability', label: 'Availability' },
  { value: 'financial', label: 'Financial' },
  { value: 'reputation', label: 'Reputation' },
  { value: 'regulatory', label: 'Regulatory' },
  { value: 'safety', label: 'Safety' },
  { value: 'privacy', label: 'Privacy' },
  { value: 'operational', label: 'Operational' },
  { value: 'strategic', label: 'Strategic' },
  { value: 'bias', label: 'Bias' },
  { value: 'discrimination', label: 'Discrimination' },
  { value: 'fairness', label: 'Fairness' },
  { value: 'human-rights', label: 'Human rights' },
  { value: 'environmental', label: 'Environmental' },
  { value: 'societal', label: 'Societal' },
  { value: 'psychological', label: 'Psychological' },
  { value: 'physical', label: 'Physical' },
  { value: 'health', label: 'Health' },
]

// backend/apps/threat_models/models.py METHODOLOGIES (custom names are also
// accepted by the API, so a model's list is typed as string[]).
export type Methodology =
  | 'STRIDE'
  | 'LINDDUN'
  | 'PASTA'
  | 'MAESTRO'
  | 'OWASP'
  | 'TRIKE'
  | 'VAST'
  | 'ATFAA'
  | 'attack-tree'

export const METHODOLOGIES: LabeledValue<Methodology>[] = [
  { value: 'STRIDE', label: 'STRIDE' },
  { value: 'LINDDUN', label: 'LINDDUN' },
  { value: 'PASTA', label: 'PASTA' },
  { value: 'MAESTRO', label: 'MAESTRO' },
  { value: 'OWASP', label: 'OWASP' },
  { value: 'TRIKE', label: 'TRIKE' },
  { value: 'VAST', label: 'VAST' },
  { value: 'ATFAA', label: 'ATFAA' },
  { value: 'attack-tree', label: 'Attack tree' },
]
export const DEFAULT_METHODOLOGIES: Methodology[] = ['STRIDE']

// backend/apps/threat_models/models.py LIFECYCLE_PHASES
export type LifecyclePhase =
  | 'design'
  | 'pre-build'
  | 'build'
  | 'post-build'
  | 'operations'
  | 'discovery'
  | 'decommission'

export const LIFECYCLE_PHASES: LabeledValue<LifecyclePhase>[] = [
  { value: 'design', label: 'Design' },
  { value: 'pre-build', label: 'Pre-build' },
  { value: 'build', label: 'Build' },
  { value: 'post-build', label: 'Post-build' },
  { value: 'operations', label: 'Operations' },
  { value: 'discovery', label: 'Discovery' },
  { value: 'decommission', label: 'Decommission' },
]

/** Review frequency presets as ISO 8601 durations (ThreatModel.review_frequency). */
export const REVIEW_FREQUENCY_PRESETS: LabeledValue<string>[] = [
  { value: 'P1M', label: 'Monthly' },
  { value: 'P3M', label: 'Quarterly' },
  { value: 'P6M', label: 'Half-yearly' },
  { value: 'P1Y', label: 'Yearly' },
]

// backend/apps/threat_models/models.py ASSUMPTION_TOPICS and Assumption.Validity
export type AssumptionTopic =
  | 'availability'
  | 'business'
  | 'compliance'
  | 'operational'
  | 'performance'
  | 'security'
  | 'technical'

export const ASSUMPTION_TOPICS: LabeledValue<AssumptionTopic>[] = [
  { value: 'security', label: 'Security' },
  { value: 'technical', label: 'Technical' },
  { value: 'business', label: 'Business' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'operational', label: 'Operational' },
  { value: 'availability', label: 'Availability' },
  { value: 'performance', label: 'Performance' },
]

export type AssumptionValidity = 'unverified' | 'verified' | 'invalid' | 'unknown'

export const ASSUMPTION_VALIDITY: LabeledValue<AssumptionValidity>[] = [
  { value: 'unverified', label: 'Unverified' },
  { value: 'verified', label: 'Verified' },
  { value: 'invalid', label: 'Invalid' },
  { value: 'unknown', label: 'Unknown' },
]

// backend/apps/threat_models/models.py BusinessObjective.Criticality
export type BusinessObjectiveCriticality = 'minimal' | 'low' | 'moderate' | 'high' | 'critical'

export const BUSINESS_OBJECTIVE_CRITICALITIES: LabeledValue<BusinessObjectiveCriticality>[] = [
  { value: 'minimal', label: 'Minimal' },
  { value: 'low', label: 'Low' },
  { value: 'moderate', label: 'Moderate' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

// backend/apps/threat_models/models.py MODEL_TYPES (Blueprint.model_types)
export type ModelType =
  | 'architecture'
  | 'behavioral'
  | 'conceptual'
  | 'data-flow'
  | 'deployment'
  | 'logical'
  | 'network'
  | 'operational'
  | 'physical'
  | 'process'

export const MODEL_TYPES: LabeledValue<ModelType>[] = [
  { value: 'data-flow', label: 'Data flow' },
  { value: 'architecture', label: 'Architecture' },
  { value: 'behavioral', label: 'Behavioral' },
  { value: 'conceptual', label: 'Conceptual' },
  { value: 'deployment', label: 'Deployment' },
  { value: 'logical', label: 'Logical' },
  { value: 'network', label: 'Network' },
  { value: 'operational', label: 'Operational' },
  { value: 'physical', label: 'Physical' },
  { value: 'process', label: 'Process' },
]

// backend/apps/threat_models/models.py ThreatModelRelationship.RelationType,
// worded from this model's side (plan J15).
export type RelationType = 'depends_on' | 'subsystem_of' | 'related_to' | 'superseded_by'

export const RELATION_TYPES: LabeledValue<RelationType>[] = [
  { value: 'related_to', label: 'is related to' },
  { value: 'depends_on', label: 'depends on' },
  { value: 'subsystem_of', label: 'is a subsystem of' },
  { value: 'superseded_by', label: 'is superseded by' },
]
export const DEFAULT_RELATION_TYPE: RelationType = 'related_to'

// backend/apps/threats/models.py ThreatIntent and ThreatAccessLevel
export type ThreatIntent = 'accidental' | 'opportunistic' | 'targeted' | 'persistent'
export const THREAT_INTENTS: LabeledValue<ThreatIntent>[] = [
  { value: 'accidental', label: 'Accidental' },
  { value: 'opportunistic', label: 'Opportunistic' },
  { value: 'targeted', label: 'Targeted' },
  { value: 'persistent', label: 'Persistent' },
]

export type ThreatAccessLevel = 'none' | 'external' | 'internal' | 'privileged' | 'physical'
export const THREAT_ACCESS_LEVELS: LabeledValue<ThreatAccessLevel>[] = [
  { value: 'none', label: 'None' },
  { value: 'external', label: 'External' },
  { value: 'internal', label: 'Internal' },
  { value: 'privileged', label: 'Privileged' },
  { value: 'physical', label: 'Physical' },
]

// Template Categories (freeform — labels for known slugs, auto-format for unknown)
export type TemplateCategory = string

const KNOWN_CATEGORY_LABELS: Record<string, string> = {
  webApplication: 'Web Application',
  mobileApplication: 'Mobile Application',
  microservices: 'Microservices',
  dataPipeline: 'Data Pipeline',
  authentication: 'Authentication',
  paymentProcessing: 'Payment Processing',
  cloudInfrastructure: 'Cloud Infrastructure',
  serverless: 'Serverless',
  ai: 'AI',
  iot: 'IoT',
  api: 'API',
  apiGateway: 'API Gateway',
  other: 'Other',
}

export function formatCategoryLabel(category: string): string {
  if (KNOWN_CATEGORY_LABELS[category]) {
    return KNOWN_CATEGORY_LABELS[category]
  }
  // Auto-format: split camelCase, hyphens, underscores → title case
  return category
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

// Data Sensitivity Tags — shared by DataAsset.data_sensitivity and edge dataClassification
// Aligned value set: edges classify what flows through them, assets classify what they contain
export type DataSensitivityTag = string

export const DATA_SENSITIVITY_TAG_CONFIG: Record<string, { label: string; description: string }> = {
  pii: { label: 'PII', description: 'Personally Identifiable Information' },
  phi: { label: 'PHI', description: 'Protected Health Information' },
  fin: { label: 'Financial', description: 'Financial Data' },
  ip: { label: 'IP', description: 'Intellectual Property' },
  cred: { label: 'Credentials', description: 'Credentials & Secrets' },
  biz: { label: 'Business', description: 'Business Critical Data' },
  gov: { label: 'Government', description: 'Government/Regulatory Data' },
  pci: { label: 'PCI', description: 'Payment Card Industry Data' },
  op: { label: 'Operational', description: 'Operational Data' },
}

// DataClassification is the same tag set, used on edges
export type DataClassification = DataSensitivityTag
export const DATA_CLASSIFICATIONS: DataClassification[] = Object.keys(DATA_SENSITIVITY_TAG_CONFIG) as DataClassification[]

// Protocols for data flows
export type Protocol =
  | 'HTTP'
  | 'HTTPS'
  | 'gRPC'
  | 'WebSocket'
  | 'TCP'
  | 'UDP'
  | 'MQTT'
  | 'AMQP'
  | 'SQL'
  | 'Custom'

export const PROTOCOLS: Protocol[] = [
  'HTTP',
  'HTTPS',
  'gRPC',
  'WebSocket',
  'TCP',
  'UDP',
  'MQTT',
  'AMQP',
  'SQL',
  'Custom',
]

// Data Sensitivity for nodes
export type DataSensitivity = 'public' | 'internal' | 'confidential'

export const DATA_SENSITIVITY_CONFIG: Record<DataSensitivity, { label: string; color: string }> = {
  public: { label: 'Public', color: '#22c55e' },
  internal: { label: 'Internal', color: '#eab308' },
  confidential: { label: 'Confidential', color: '#ef4444' },
}

// Diagram types
export type DiagramTypeValue = 'context' | 'level1' | 'level2'
export type ThreatFramework = 'stride' | 'linddun' | 'cia'

// Node types for DFD
// humanActor = external human entity (customer, admin, attacker)
// systemActor = external non-human system (third-party API, partner system)
// stickyNote and table carry no DFD semantics — they annotate the diagram and
// are excluded from threat analysis.
export type DiagramNodeType = 'process' | 'datastore' | 'humanActor' | 'systemActor' | 'trustZone' | 'systemScope' | 'stickyNote' | 'table'

// Compliance/Security Standards
export type SecurityStandard =
  | 'PCI-DSS'
  | 'SOC2'
  | 'ISO27001'
  | 'NIST'
  | 'OWASP'
  | 'GDPR'
  | 'HIPAA'
  | 'DORA'
  | 'CRA'

export const SECURITY_STANDARDS: Record<SecurityStandard, { label: string; description: string }> = {
  'PCI-DSS': {
    label: 'PCI-DSS',
    description: 'Payment Card Industry Data Security Standard',
  },
  SOC2: {
    label: 'SOC 2',
    description: 'Service Organization Control 2',
  },
  ISO27001: {
    label: 'ISO 27001',
    description: 'Information Security Management System',
  },
  NIST: {
    label: 'NIST CSF',
    description: 'NIST Cybersecurity Framework',
  },
  OWASP: {
    label: 'OWASP',
    description: 'Open Web Application Security Project',
  },
  GDPR: {
    label: 'GDPR',
    description: 'General Data Protection Regulation',
  },
  HIPAA: {
    label: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
  },
  DORA: {
    label: 'DORA',
    description: 'Digital Operational Resilience Act',
  },
  CRA: {
    label: 'CRA',
    description: 'Cyber Resilience Act',
  },
}
