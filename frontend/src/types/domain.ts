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
