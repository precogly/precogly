/**
 * CycloneDX 2.0 TM-BOM reader and writer for the guest editor (plan 11.9).
 *
 * Written slice for slice in the shape the backend adapter emits
 * (`backend/apps/threat_models/tmbom/exporter/*`): one blueprint with zones,
 * assets, data stores, data sets, boundaries with crossing requirements,
 * flows with type and authentication, the canvas as a visualization
 * attachment, scenarios with `threats` and every affected asset, abstract
 * threats, controls with every link, derived trust boundaries, the number
 * counters and the document identity. Enum values and property names come
 * from `cyclonedx-spec.generated.ts`.
 *
 * Everything the guest editor does not model is kept as it arrived and
 * written back in place (plan 9.7): further blueprints, risks, business
 * objectives, the review block, actors, use cases, ratings beyond the level,
 * other tools' properties. Opening a file is editing that document: the
 * serial number stays and the version rises when the content changed (I4).
 *
 * Import is lenient: anything that cannot be read as it is becomes a warning
 * for the UI, never a silent drop (decision D17: no run-time schema check).
 */

import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { DFDNotationStyle } from '@/features/dfd-editor/types/notation'
import {
  getAuthentication,
  getBoundaryType,
  getComponentKind,
  getFlowType,
  getZoneType,
  kindForNodeType,
} from '@/features/dfd-editor/lib/canvas-defaults'
import { getTrustLevel } from '@/features/dfd-editor/lib/zone-trust-level'
import { DATA_SENSITIVITY_CONFIG, isDataLikeFlowType, type STRIDECategory } from '@/types/domain'
import {
  emptyKeptContent,
  type GuestAssumption,
  type GuestCountermeasure,
  type GuestDataAsset,
  type GuestDocumentState,
  type GuestKeptContent,
  type GuestOutOfScopeItem,
  type GuestRatingLevel,
  type GuestSystemContext,
  type GuestTargetRef,
  type GuestThreat,
  type ThreatStatus,
  type ControlFunction,
  type ControlNature,
} from '../types'
import type {
  CycloneDxAssumption,
  CycloneDxAsset,
  CycloneDxBlueprint,
  CycloneDxBoundary,
  CycloneDxControl,
  CycloneDxDataProfile,
  CycloneDxDataSet,
  CycloneDxDataStore,
  CycloneDxDocument,
  CycloneDxFlow,
  CycloneDxMetadataComponent,
  CycloneDxProperty,
  CycloneDxScenario,
  CycloneDxThreat,
  CycloneDxThreatCategory,
  CycloneDxTrustBoundary,
  CycloneDxTypeValue,
  CycloneDxVisualization,
  CycloneDxZone,
} from './cyclonedx-types'
import {
  ASSET_TYPES,
  AUTHENTICATION_TYPES,
  AUTHORIZATION_TYPES,
  BOUNDARY_TYPES,
  CANVAS_SESSION_KEYS,
  CONTROL_CATEGORIES,
  DATA_CLASSIFICATIONS,
  DATA_STORE_TYPES,
  DATA_STORE_TYPE_TO_SPEC,
  FLOW_TYPES,
  PRECOGLY_DFD_MEDIA_TYPE,
  PROPERTY_OWNER,
  SESSION_EDITOR_KEYS,
  THREAT_CATEGORIES,
  ZONE_TYPES,
  REF_KEYS,
} from './cyclonedx-spec.generated'
import {
  jsonPropertyItems,
  known,
  mergeProperties,
  readProperties,
  stableStringify,
  type KnownProperty,
} from './cyclonedx-properties'
import {
  decodeCanvasContent,
  edgeForFile,
  encodeCanvasContent,
  keysToCamelCase,
  nodeForFile,
} from './cyclonedx-canvas'
import {
  countermeasureFileStatus,
  deriveThreatStatus,
  targetTypeForEdge,
  targetTypeForNode,
} from './guest-model'

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

export const GUEST_TOOL_NAME = 'Precogly Guest Editor'
export const GUEST_TOOL_VERSION = '2.0.0'

/** Session facts travel as a foreign property so the backend keeps them untouched. */
export const GUEST_SESSION_PROPERTY = 'precogly-guest:session'

const RATING_LEVELS: readonly GuestRatingLevel[] = ['info', 'low', 'medium', 'high', 'critical']
const THREAT_STATUSES: readonly ThreatStatus[] = ['open', 'accept', 'mitigate', 'delegate', 'eliminate']
const CONTROL_FUNCTIONS: readonly ControlFunction[] = ['preventive', 'detective', 'corrective', 'deterrent', 'recovery', 'compensating']
const CONTROL_NATURES: readonly ControlNature[] = ['technical', 'administrative', 'physical']
const STRIDE_VALUES = new Set<string>(THREAT_CATEGORIES.STRIDE)

const CRITICALITY_TO_SPEC: Record<GuestSystemContext['systemInfo']['criticality'], string> = {
  low: 'low',
  medium: 'moderate',
  high: 'high',
  critical: 'critical',
}
const SPEC_TO_CRITICALITY: Record<string, GuestSystemContext['systemInfo']['criticality']> = {
  minimal: 'low',
  low: 'low',
  moderate: 'medium',
  high: 'high',
  critical: 'critical',
}

/** The first Precogly value for each spec data store type (the backend's `SPEC_TO_DATA_STORE_TYPE`). */
const SPEC_TO_DATA_STORE_TYPE: Record<string, string> = {}
for (const [ours, spec] of Object.entries(DATA_STORE_TYPE_TO_SPEC)) {
  if (!(spec in SPEC_TO_DATA_STORE_TYPE)) SPEC_TO_DATA_STORE_TYPE[spec] = ours
}

/** Canvas key -> sessionManagement key (the backend's `CANVAS_SESSION_KEYS`, camelCased). */
const SESSION_CANVAS_TO_SPEC: Record<string, string> = Object.fromEntries(
  Object.entries(CANVAS_SESSION_KEYS).map(([canvasKey, specKey]) => [
    canvasKey.replace(/_([a-z])/g, (_match, letter: string) => letter.toUpperCase()),
    specKey,
  ])
)
const SESSION_SPEC_TO_CANVAS: Record<string, string> = Object.fromEntries(
  Object.entries(SESSION_CANVAS_TO_SPEC).map(([canvasKey, specKey]) => [specKey, canvasKey])
)

/** Keys whose values are refs into the same document (the backend's `REF_KEYS`, generated). */
const REF_KEY_SET = new Set<string>(REF_KEYS)

const BLUEPRINT_KNOWN_KEYS = new Set([
  'bom-ref', 'name', 'description', 'modelTypes', 'scope', 'assets', 'dataStores', 'dataSets',
  'zones', 'boundaries', 'flows', 'assumptions', 'visualizations',
])
const DOCUMENT_KNOWN_KEYS = new Set([
  'specFormat', 'specVersion', 'serialNumber', 'version', 'metadata', 'blueprints', 'threats',
  'controls', 'properties',
])
const METADATA_KNOWN_KEYS = new Set(['timestamp', 'tools', 'component'])
const THREATS_SECTION_KNOWN_KEYS = new Set(['threats', 'scenarios', 'trustBoundaries'])
const ENTRY_KNOWN_KEYS: Record<string, Set<string>> = {
  zones: new Set(['bom-ref', 'name', 'description', 'type', 'parent', 'properties']),
  assets: new Set(['bom-ref', 'name', 'description', 'type', 'zone', 'properties']),
  dataStores: new Set(['bom-ref', 'name', 'description', 'type', 'zone', 'properties']),
  flows: new Set([
    'bom-ref', 'name', 'description', 'type', 'source', 'destination', 'encrypted', 'protocols',
    'authentication', 'properties',
  ]),
  boundaries: new Set(['bom-ref', 'name', 'type', 'zones', 'crossingRequirements', 'sessionManagement', 'properties']),
  dataSets: new Set(['bom-ref', 'name', 'description', 'dataProfiles', 'properties']),
  assumptions: new Set(['bom-ref', 'description', 'validity', 'topic']),
  scenarios: new Set(['bom-ref', 'name', 'threats', 'description', 'affectedAssets', 'riskScore', 'properties']),
  controls: new Set(['bom-ref', 'name', 'description', 'category', 'status', 'appliesTo', 'properties']),
}

type JsonObject = Record<string, unknown>

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function typeName(value: unknown): string {
  if (typeof value === 'string') return value
  if (isObject(value)) return asString(value.name)
  return ''
}

function customType(name: string): CycloneDxTypeValue {
  return { name }
}

function specOrCustom(value: string, allowed: readonly string[]): CycloneDxTypeValue {
  return allowed.includes(value) ? value : customType(value)
}

function deepClone<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T)
}

function uuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (char) => {
    const random = (Math.random() * 16) | 0
    const value = char === 'x' ? random : (random & 0x3) | 0x8
    return value.toString(16)
  })
}

const SERIAL_PATTERN = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function newSerialNumber(): string {
  return `urn:uuid:${uuid()}`
}

export function newDocumentState(): GuestDocumentState {
  return {
    serialNumber: newSerialNumber(),
    version: 1,
    exportDigest: null,
    nextThreatNumber: 1,
    nextCountermeasureNumber: 1,
    kept: emptyKeptContent(),
  }
}

// ---------------------------------------------------------------------------
// Digest (plan 9.3 row 13: the version rises when the content changed)
// ---------------------------------------------------------------------------

const BOM_LINK_VERSION = /^(urn:cdx:[0-9a-f-]{36})\/[1-9][0-9]*(#.*)?$/
const DIGEST_BLANKED_KEYS = new Set(['timestamp', 'reviewDate', 'approvalDate'])

function stripForDigest(node: unknown, key?: string): unknown {
  if (Array.isArray(node)) return node.map((item) => stripForDigest(item))
  if (isObject(node)) {
    const result: JsonObject = {}
    for (const [childKey, value] of Object.entries(node)) {
      result[childKey] = stripForDigest(value, childKey)
    }
    return result
  }
  if (typeof node === 'string') {
    if (key && DIGEST_BLANKED_KEYS.has(key)) return ''
    const match = BOM_LINK_VERSION.exec(node)
    if (match) return match[1] + (match[2] ?? '')
  }
  return node
}

function hash53(text: string): string {
  let h1 = 0xdeadbeef
  let h2 = 0x41c6ce57
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    h1 = Math.imul(h1 ^ code, 2654435761)
    h2 = Math.imul(h2 ^ code, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0')
}

/** The digest of a document without its serial number, version and timestamps. */
export function contentDigest(document: CycloneDxDocument): string {
  const stripped = stripForDigest(document) as JsonObject
  delete stripped.serialNumber
  delete stripped.version
  return hash53(stableStringify(stripped))
}

// ---------------------------------------------------------------------------
// Refs
// ---------------------------------------------------------------------------

function collectRefs(node: unknown, found: Set<string>): Set<string> {
  if (Array.isArray(node)) {
    for (const item of node) collectRefs(item, found)
  } else if (isObject(node)) {
    if (typeof node['bom-ref'] === 'string') found.add(node['bom-ref'])
    for (const value of Object.values(node)) collectRefs(value, found)
  }
  return found
}

class RefBook {
  private readonly used = new Set<string>()

  constructor(reserved: Iterable<string>) {
    for (const ref of reserved) this.used.add(ref)
  }

  /** A ref the file gave an element keeps it; a derived one is de-clashed. */
  claim(stored: string | undefined, derived: string): string {
    if (stored && stored.length > 0) {
      this.used.add(stored)
      return stored
    }
    let candidate = derived
    while (this.used.has(candidate)) candidate += '-local'
    this.used.add(candidate)
    return candidate
  }

  has(ref: string): boolean {
    return this.used.has(ref)
  }
}

function storedRef(data: unknown): string | undefined {
  return isObject(data) && typeof data.bomRef === 'string' && data.bomRef ? data.bomRef : undefined
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export interface GuestExportInput {
  title: string
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  threats: GuestThreat[]
  countermeasures: GuestCountermeasure[]
  systemContext: GuestSystemContext
  notationStyle?: DFDNotationStyle
  documentState: GuestDocumentState
}

export interface GuestExportResult {
  document: CycloneDxDocument
  json: string
  /** The version written: the state's, raised when the content changed. */
  version: number
  digest: string
  /** What the export had to repair (stale refs in kept content, K2). */
  warnings: string[]
}

interface ElementRefs {
  nodeRefs: Map<string, string>
  edgeRefs: Map<string, string>
  threatRefs: Map<string, string>
  countermeasureRefs: Map<string, string>
  dataSetRefs: Map<string, string>
  assumptionRefs: Map<string, string>
  systemRef: string
}

function nodeData(node: DiagramNode): JsonObject {
  return (node.data ?? {}) as JsonObject
}

function edgeData(edge: DiagramEdge): JsonObject {
  return (edge.data ?? {}) as JsonObject
}

function nodeLabel(node: DiagramNode, fallback: string): string {
  return asString(nodeData(node).label) || fallback
}

function keptEntry(kept: GuestKeptContent, ref: string): JsonObject {
  return kept.entries[ref] ?? {}
}

function keptProperties(entry: JsonObject): CycloneDxProperty[] | undefined {
  return Array.isArray(entry.properties) ? (entry.properties as CycloneDxProperty[]) : undefined
}

/** The entry's unknown keys, without the ones the guest editor regenerates. */
function passthroughKeys(entry: JsonObject, regenerated: Iterable<string>): JsonObject {
  const skip = new Set(regenerated)
  const result: JsonObject = {}
  for (const [key, value] of Object.entries(entry)) {
    if (!skip.has(key) && !key.startsWith('__')) result[key] = deepClone(value)
  }
  return result
}

function withProperties<T extends JsonObject>(entry: T, properties: CycloneDxProperty[]): T {
  const target: JsonObject = entry
  if (properties.length > 0) target.properties = properties
  else delete target.properties
  return entry
}

/** A kept custom type object (`{name, description?}`) as the spec's type value. */
function keptTypeValue(value: JsonObject): CycloneDxTypeValue {
  return value as unknown as CycloneDxTypeValue
}

function orderSection<T extends JsonObject>(
  kept: GuestKeptContent,
  section: string,
  generated: Map<string, T>,
  hidden: readonly JsonObject[]
): JsonObject[] {
  const byRef = new Map<string, JsonObject>()
  for (const [ref, entry] of generated) byRef.set(ref, entry)
  const hiddenWithoutRef: JsonObject[] = []
  for (const entry of hidden) {
    const ref = entry['bom-ref']
    if (typeof ref === 'string' && ref) byRef.set(ref, deepClone(entry))
    else hiddenWithoutRef.push(deepClone(entry))
  }
  const result: JsonObject[] = []
  const emitted = new Set<string>()
  for (const ref of kept.entryOrder[section] ?? []) {
    const entry = byRef.get(ref)
    if (entry && !emitted.has(ref)) {
      result.push(entry)
      emitted.add(ref)
    }
  }
  for (const [ref, entry] of byRef) {
    if (!emitted.has(ref)) {
      result.push(entry)
      emitted.add(ref)
    }
  }
  result.push(...hiddenWithoutRef)
  return result
}

function nearestZoneRef(node: DiagramNode, nodesById: Map<string, DiagramNode>, refs: ElementRefs): string | undefined {
  let parentId = node.parentId
  const visited = new Set<string>()
  while (parentId && !visited.has(parentId)) {
    visited.add(parentId)
    const parent = nodesById.get(parentId)
    if (!parent) return undefined
    if (parent.type === 'trustZone') return refs.nodeRefs.get(parent.id)
    parentId = parent.parentId
  }
  return undefined
}

function parentComponentRef(node: DiagramNode, nodesById: Map<string, DiagramNode>, refs: ElementRefs): string | undefined {
  if (!node.parentId) return undefined
  const parent = nodesById.get(node.parentId)
  if (!parent || parent.type === 'trustZone') return undefined
  return refs.nodeRefs.get(parent.id)
}

function categoryForNode(node: DiagramNode): string {
  switch (node.type) {
    case 'datastore':
      return 'datastore'
    case 'humanActor':
      return 'external_human_actor'
    case 'systemActor':
      return 'external_system_actor'
    default:
      return 'process'
  }
}

function typeListForFile(values: readonly string[], allowed: readonly string[]): CycloneDxTypeValue[] {
  return values.filter((value) => value !== '').map((value) => specOrCustom(value, allowed))
}

function buildZone(node: DiagramNode, nodesById: Map<string, DiagramNode>, refs: ElementRefs, kept: GuestKeptContent): CycloneDxZone {
  const ref = refs.nodeRefs.get(node.id)!
  const data = nodeData(node)
  const entry = keptEntry(kept, ref)
  const zone: CycloneDxZone = {
    ...passthroughKeys(entry, ENTRY_KNOWN_KEYS.zones),
    'bom-ref': ref,
    name: nodeLabel(node, 'Zone'),
    type: data.zoneType === undefined && isObject(entry.__customType) ? keptTypeValue(deepClone(entry.__customType as JsonObject)) : getZoneType(data),
  }
  const description = asString(data.description)
  if (description) zone.description = description
  const parentRef = node.parentId ? refs.nodeRefs.get(node.parentId) : undefined
  const parent = node.parentId ? nodesById.get(node.parentId) : undefined
  if (parentRef && parent?.type === 'trustZone') zone.parent = parentRef
  const trustLevel = getTrustLevel(data)
  return withProperties(zone, mergeProperties(keptProperties(entry), [
    known(PROPERTY_OWNER.ZONE, 'precogly:trust-level', trustLevel ?? undefined),
  ]))
}

function buildAsset(node: DiagramNode, nodesById: Map<string, DiagramNode>, refs: ElementRefs, kept: GuestKeptContent): CycloneDxAsset {
  const ref = refs.nodeRefs.get(node.id)!
  const data = nodeData(node)
  const entry = keptEntry(kept, ref)
  const asset: CycloneDxAsset = {
    ...passthroughKeys(entry, ENTRY_KNOWN_KEYS.assets),
    'bom-ref': ref,
    name: nodeLabel(node, node.type ?? 'Component'),
    type: data.kind === undefined && isObject(entry.__customType) ? keptTypeValue(deepClone(entry.__customType as JsonObject)) : getComponentKind(data, node.type),
  }
  const description = asString(data.description)
  if (description) asset.description = description
  const zoneRef = nearestZoneRef(node, nodesById, refs)
  if (zoneRef) asset.zone = zoneRef
  const actorType = node.type === 'humanActor' ? asString(data.actorType) : node.type === 'systemActor' ? asString(data.systemType) : ''
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.ASSET, 'precogly:category', categoryForNode(node)),
    known(PROPERTY_OWNER.ASSET, 'precogly:actor-type', actorType || undefined),
    known(PROPERTY_OWNER.ASSET, 'precogly:data-sensitivity', asString(data.dataSensitivity) || asString(entry.__dataSensitivity) || undefined),
    known(PROPERTY_OWNER.ASSET, 'precogly:parent', parentComponentRef(node, nodesById, refs)),
  ]
  return withProperties(asset, mergeProperties(keptProperties(entry), properties))
}

function dataStoreTypeForFile(data: JsonObject, entry: JsonObject): { type: CycloneDxTypeValue; ownValue: string | undefined } {
  const raw = asString(data.dataStoreType).trim()
  if (!raw) {
    if (isObject(entry.__customType)) return { type: keptTypeValue(deepClone(entry.__customType as JsonObject)), ownValue: undefined }
    return { type: customType('unspecified'), ownValue: undefined }
  }
  const spec = DATA_STORE_TYPE_TO_SPEC[raw.toLowerCase()]
  if (spec) return { type: spec, ownValue: raw }
  return { type: customType(raw), ownValue: undefined }
}

function buildDataStore(node: DiagramNode, nodesById: Map<string, DiagramNode>, refs: ElementRefs, kept: GuestKeptContent): CycloneDxDataStore {
  const ref = refs.nodeRefs.get(node.id)!
  const data = nodeData(node)
  const entry = keptEntry(kept, ref)
  const { type, ownValue } = dataStoreTypeForFile(data, entry)
  const store: CycloneDxDataStore = {
    ...passthroughKeys(entry, ENTRY_KNOWN_KEYS.dataStores),
    'bom-ref': ref,
    name: nodeLabel(node, 'Data store'),
    type,
  }
  const description = asString(data.description)
  if (description) store.description = description
  const zoneRef = nearestZoneRef(node, nodesById, refs)
  if (zoneRef) store.zone = zoneRef
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.DATA_STORE, 'precogly:data-store-type', ownValue),
    known(PROPERTY_OWNER.ASSET, 'precogly:data-sensitivity', asString(data.dataSensitivity) || asString(entry.__dataSensitivity) || undefined),
    known(PROPERTY_OWNER.ASSET, 'precogly:parent', parentComponentRef(node, nodesById, refs)),
  ]
  return withProperties(store, mergeProperties(keptProperties(entry), properties))
}

function flowNameForFile(edge: DiagramEdge, nodesById: Map<string, DiagramNode>): string {
  const label = asString(edgeData(edge).label)
  if (label) return label
  const sourceLabel = nodesById.get(edge.source) ? nodeLabel(nodesById.get(edge.source)!, edge.source) : edge.source
  const targetLabel = nodesById.get(edge.target) ? nodeLabel(nodesById.get(edge.target)!, edge.target) : edge.target
  return `${sourceLabel} to ${targetLabel}`
}

function buildFlow(edge: DiagramEdge, nodesById: Map<string, DiagramNode>, refs: ElementRefs, kept: GuestKeptContent): CycloneDxFlow | null {
  const ref = refs.edgeRefs.get(edge.id)!
  const sourceRef = refs.nodeRefs.get(edge.source)
  const destinationRef = refs.nodeRefs.get(edge.target)
  if (!sourceRef || !destinationRef) return null
  const data = edgeData(edge)
  const entry = keptEntry(kept, ref)
  const flowType = data.flowType === undefined && isObject(entry.__customType) ? null : getFlowType(data)
  const dataLike = flowType === null ? true : isDataLikeFlowType(flowType)
  const flow: CycloneDxFlow = {
    ...passthroughKeys(entry, ENTRY_KNOWN_KEYS.flows),
    'bom-ref': ref,
    name: flowNameForFile(edge, nodesById),
    type: flowType ?? (keptTypeValue(deepClone(entry.__customType as JsonObject))),
    source: sourceRef,
    destination: destinationRef,
  }
  const description = asString(data.description)
  if (description) flow.description = description
  if (dataLike && data.encrypted === true) flow.encrypted = true
  const protocol = asString(data.protocol)
  if (dataLike && protocol) flow.protocols = [protocol]
  const authentication = getAuthentication(data)
  if (authentication.length > 0) flow.authentication = typeListForFile(authentication, AUTHENTICATION_TYPES)
  const port = typeof data.port === 'number' && Number.isInteger(data.port) ? data.port : undefined
  const classification = Array.isArray(data.dataClassification)
    ? data.dataClassification.filter((item): item is string => typeof item === 'string' && item !== '')
    : []
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.FLOW, 'precogly:port', dataLike ? port : undefined),
    known(PROPERTY_OWNER.FLOW, 'precogly:has-sensitive-data', data.hasSensitiveData === true ? true : undefined),
    known(PROPERTY_OWNER.FLOW, 'precogly:data-classification', classification.length > 0 ? classification : undefined),
  ]
  return withProperties(flow, mergeProperties(keptProperties(entry), properties))
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item !== '') : []
}

function buildBoundary(edge: DiagramEdge, refs: ElementRefs, kept: GuestKeptContent): CycloneDxBoundary | null {
  const ref = refs.edgeRefs.get(edge.id)!
  const zoneA = refs.nodeRefs.get(edge.source)
  const zoneB = refs.nodeRefs.get(edge.target)
  if (!zoneA || !zoneB) return null
  const data = edgeData(edge)
  const entry = keptEntry(kept, ref)
  const zones = [zoneA, zoneB]
  // Zones beyond the first two (M11) travel with the entry; a stale one is
  // dropped by the ref repair at the end of the export.
  for (const extra of stringList(entry.__extraZones)) {
    if (!zones.includes(extra)) zones.push(extra)
  }
  const boundary: CycloneDxBoundary = {
    ...passthroughKeys(entry, ENTRY_KNOWN_KEYS.boundaries),
    'bom-ref': ref,
    zones,
    type: data.boundaryType === undefined && isObject(entry.__customType) ? keptTypeValue(deepClone(entry.__customType as JsonObject)) : getBoundaryType(data),
  }
  const label = asString(data.label)
  if (label) boundary.name = label
  const requirements: JsonObject = isObject(entry.__crossingRequirements) ? deepClone(entry.__crossingRequirements) : {}
  const authentication = stringList(data.authenticationMethods)
  if (authentication.length > 0) requirements.authentication = typeListForFile(authentication, AUTHENTICATION_TYPES)
  else delete requirements.authentication
  const authorization = stringList(data.accessControlMethods)
  if (authorization.length > 0) requirements.authorization = typeListForFile(authorization, AUTHORIZATION_TYPES)
  else delete requirements.authorization
  for (const key of ['dataValidation', 'logging', 'monitoring'] as const) {
    if (data[key] === true) requirements[key] = true
    else delete requirements[key]
  }
  const rateLimit = asString(data.rateLimit)
  if (rateLimit) requirements.rateLimit = rateLimit
  else delete requirements.rateLimit
  if (Object.keys(requirements).length > 0) boundary.crossingRequirements = requirements
  const session: JsonObject = isObject(entry.__sessionManagement) ? deepClone(entry.__sessionManagement) : {}
  for (const key of SESSION_EDITOR_KEYS) delete session[key]
  for (const [canvasKey, specKey] of Object.entries(SESSION_CANVAS_TO_SPEC)) {
    const raw = data[canvasKey]
    if (raw === undefined || raw === null || raw === '') continue
    if (specKey.endsWith('Ttl')) {
      const number = typeof raw === 'number' ? raw : Number.parseInt(String(raw), 10)
      if (Number.isInteger(number) && number >= 0) session[specKey] = number
    } else {
      session[specKey] = Boolean(raw)
    }
  }
  if (Object.keys(session).length > 0) boundary.sessionManagement = session
  return withProperties(boundary, mergeProperties(keptProperties(entry), []))
}

function buildDataSet(asset: GuestDataAsset, refs: ElementRefs): CycloneDxDataSet {
  const ref = refs.dataSetRefs.get(asset.id)!
  const passthrough = asset.passthrough ?? {}
  const entry: CycloneDxDataSet = {
    ...passthroughKeys(passthrough, ENTRY_KNOWN_KEYS.dataSets),
    'bom-ref': ref,
    name: asset.name,
    description: asset.description || asset.name,
  }
  const classification = asset.classification.trim().toLowerCase()
  const keptProfile = isObject(passthrough.__profile) ? passthrough.__profile : null
  if (classification || asset.complianceTags.length > 0 || keptProfile) {
    const profile: CycloneDxDataProfile = {
      ...(keptProfile ? passthroughKeys(keptProfile, ['bom-ref', 'name', 'classification', 'regulations']) : {}),
      'bom-ref': `${ref}-profile`,
      name: `${asset.name} profile`,
    }
    if (classification) {
      profile.classification = (DATA_CLASSIFICATIONS as readonly string[]).includes(classification)
        ? classification
        : customType(asset.classification)
    }
    if (asset.complianceTags.length > 0) profile.regulations = [...asset.complianceTags]
    const extraProfiles = Array.isArray(passthrough.__extraProfiles) ? deepClone(passthrough.__extraProfiles) : []
    entry.dataProfiles = [profile, ...(extraProfiles as (CycloneDxDataProfile | string)[])]
  }
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.DATA_SET, 'precogly:confidentiality', asset.confidentiality !== 'medium' ? asset.confidentiality : undefined),
    known(PROPERTY_OWNER.DATA_SET, 'precogly:integrity', asset.integrity !== 'medium' ? asset.integrity : undefined),
    known(PROPERTY_OWNER.DATA_SET, 'precogly:availability', asset.availability !== 'medium' ? asset.availability : undefined),
    known(PROPERTY_OWNER.DATA_SET, 'precogly:data-sensitivity-tags', asset.dataSensitivity.length > 0 ? [...asset.dataSensitivity] : undefined),
  ]
  return withProperties(entry, mergeProperties(keptProperties(passthrough), properties))
}

function buildAssumption(assumption: GuestAssumption, refs: ElementRefs): CycloneDxAssumption {
  const passthrough = assumption.passthrough ?? {}
  const entry: CycloneDxAssumption = {
    ...passthroughKeys(passthrough, ENTRY_KNOWN_KEYS.assumptions),
    'bom-ref': refs.assumptionRefs.get(assumption.id)!,
    description: assumption.description,
    validity: assumption.validity,
  }
  if (assumption.topic) entry.topic = assumption.topic
  else if (isObject(passthrough.__customTopic)) entry.topic = keptTypeValue(deepClone(passthrough.__customTopic))
  return entry
}

function buildScope(
  items: readonly GuestOutOfScopeItem[],
  nodes: readonly DiagramNode[],
  refs: ElementRefs,
  kept: GuestKeptContent,
  title: string
): JsonObject | null {
  if (items.length === 0 && !kept.hadScope) return null
  const byName = new Map<string, string>()
  for (const node of nodes) {
    const ref = refs.nodeRefs.get(node.id)
    if (ref && targetTypeForNode(node) === 'component' && !byName.has(nodeLabel(node, ''))) byName.set(nodeLabel(node, ''), ref)
  }
  const excluded: string[] = []
  const itemProperties: CycloneDxProperty[] = []
  for (const item of items) {
    const ref = byName.get(item.name)
    if (ref) {
      excluded.push(ref)
    } else {
      itemProperties.push({
        name: 'precogly:out-of-scope',
        value: stableStringify({ name: item.name, reason: item.reason }),
      })
    }
  }
  const scope: JsonObject = {
    ...passthroughKeys(kept.scope, ['name', 'excludedComponents', 'properties']),
    name: `${title} scope`,
  }
  for (const extra of stringList(kept.scope.__extraExcluded)) {
    if (!excluded.includes(extra)) excluded.push(extra)
  }
  if (excluded.length > 0) scope.excludedComponents = excluded
  const keptOther = (keptProperties(kept.scope) ?? []).filter((property) => property.name !== 'precogly:out-of-scope')
  const properties = [...keptOther, ...itemProperties]
  if (properties.length > 0) scope.properties = properties
  return scope
}

function riskScoreForFile(threat: GuestThreat): JsonObject {
  const kept = threat.passthrough?.riskScore
  if (isObject(kept) && kept.level === threat.level) return deepClone(kept)
  return { level: threat.level, methodology: { name: 'manual' } }
}

function buildScenario(
  threat: GuestThreat,
  countermeasures: readonly GuestCountermeasure[],
  refs: ElementRefs,
  abstractRefs: string[]
): CycloneDxScenario {
  const passthrough = threat.passthrough ?? {}
  const scenario: CycloneDxScenario = {
    ...passthroughKeys(passthrough, ENTRY_KNOWN_KEYS.scenarios),
    'bom-ref': refs.threatRefs.get(threat.id)!,
    name: threat.name,
    threats: abstractRefs,
  }
  if (threat.description) scenario.description = threat.description
  const affected = threat.wholeSystem
    ? [refs.systemRef]
    : threat.targets.map((target) => targetRef(target, refs)).filter((ref): ref is string => ref !== undefined)
  for (const hidden of threat.hiddenTargetRefs) {
    if (!affected.includes(hidden)) affected.push(hidden)
  }
  if (affected.length > 0) scenario.affectedAssets = affected
  scenario.riskScore = riskScoreForFile(threat) as CycloneDxScenario['riskScore']
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.SCENARIO, 'precogly:number', threat.number),
    known(PROPERTY_OWNER.SCENARIO, 'precogly:threat-status', deriveThreatStatus(threat, countermeasures)),
    known(PROPERTY_OWNER.SCENARIO, 'precogly:triage-status', threat.status),
    known(PROPERTY_OWNER.SCENARIO, 'precogly:decision-rationale', threat.decisionRationale?.trim() || undefined),
  ]
  return withProperties(scenario, mergeProperties(keptProperties(passthrough), properties))
}

function targetRef(target: GuestTargetRef, refs: ElementRefs): string | undefined {
  return target.type === 'component' || target.type === 'zone' ? refs.nodeRefs.get(target.id) : refs.edgeRefs.get(target.id)
}

function strideCategory(threat: GuestThreat): CycloneDxThreatCategory | null {
  return threat.category && STRIDE_VALUES.has(threat.category) ? { taxonomy: 'STRIDE', category: threat.category } : null
}

function buildAbstractThreats(
  threats: readonly GuestThreat[],
  countermeasures: readonly GuestCountermeasure[],
  refs: ElementRefs,
  kept: GuestKeptContent
): { entries: CycloneDxThreat[]; byThreat: Map<string, string[]> } {
  const byThreat = new Map<string, string[]>()
  const order: string[] = []
  const realizedBy = new Map<string, GuestThreat[]>()
  for (const threat of threats) {
    const abstractRefs = threat.abstractRefs && threat.abstractRefs.length > 0 ? [...threat.abstractRefs] : [`threat-custom-${threat.id}`]
    byThreat.set(threat.id, abstractRefs)
    for (const ref of abstractRefs) {
      if (!realizedBy.has(ref)) {
        realizedBy.set(ref, [])
        order.push(ref)
      }
      realizedBy.get(ref)!.push(threat)
    }
  }
  const ordered = [...kept.abstractThreatOrder.filter((ref) => realizedBy.has(ref)), ...order.filter((ref) => !kept.abstractThreatOrder.includes(ref))]
  const entries: CycloneDxThreat[] = []
  for (const ref of ordered) {
    const realizing = realizedBy.get(ref)!
    const first = realizing[0]
    const keptEntry = kept.abstractThreats[ref]
    const isCustom = !keptEntry || ref.startsWith('threat-custom-')
    const entry: CycloneDxThreat = keptEntry ? (deepClone(keptEntry) as CycloneDxThreat) : { 'bom-ref': ref, name: first.name }
    entry['bom-ref'] = ref
    if (isCustom) {
      entry.name = first.name
      if (first.description) entry.description = first.description
      else delete entry.description
    }
    const categories = (entry.categories ?? []).filter((category) => isObject(category) && category.taxonomy !== 'STRIDE')
    const stride = strideCategory(first)
    const keptStride = (keptEntry?.categories as CycloneDxThreatCategory[] | undefined)?.find((category) => category.taxonomy === 'STRIDE')
    if (stride) {
      if (keptStride && keptStride.category === stride.category) {
        entry.categories = deepClone(keptEntry!.categories as CycloneDxThreatCategory[])
      } else {
        entry.categories = [...categories, stride]
      }
    } else if (categories.length > 0) {
      entry.categories = categories
    } else {
      delete entry.categories
    }
    const mitigations: string[] = []
    for (const threat of realizing) {
      for (const countermeasure of countermeasures) {
        if (!countermeasure.threatIds.includes(threat.id)) continue
        const controlRef = refs.countermeasureRefs.get(countermeasure.id)!
        if (!mitigations.includes(controlRef)) mitigations.push(controlRef)
      }
    }
    if (mitigations.length > 0) entry.mitigations = mitigations
    else delete entry.mitigations
    entries.push(entry)
  }
  return { entries, byThreat }
}

function buildControl(countermeasure: GuestCountermeasure, refs: ElementRefs): CycloneDxControl {
  const passthrough = countermeasure.passthrough ?? {}
  const control: CycloneDxControl = {
    ...passthroughKeys(passthrough, ENTRY_KNOWN_KEYS.controls),
    'bom-ref': refs.countermeasureRefs.get(countermeasure.id)!,
    name: countermeasure.name,
  }
  if (countermeasure.description) control.description = countermeasure.description
  const category = countermeasure.controlFunction.find((value) => (CONTROL_CATEGORIES as readonly string[]).includes(value))
  if (category) control.category = category
  control.status = deepClone(countermeasureFileStatus(countermeasure)) as CycloneDxTypeValue
  const appliesTo = countermeasure.targets.map((target) => targetRef(target, refs)).filter((ref): ref is string => ref !== undefined)
  for (const hidden of countermeasure.hiddenTargetRefs) {
    if (!appliesTo.includes(hidden)) appliesTo.push(hidden)
  }
  if (appliesTo.length > 0) control.appliesTo = appliesTo
  const scenarioRefs = countermeasure.threatIds.map((threatId) => refs.threatRefs.get(threatId)).filter((ref): ref is string => ref !== undefined)
  const properties: KnownProperty[] = [
    known(PROPERTY_OWNER.CONTROL, 'precogly:number', countermeasure.number),
    known(PROPERTY_OWNER.CONTROL, 'precogly:control-functions', countermeasure.controlFunction.length > 0 ? [...countermeasure.controlFunction] : undefined),
    known(PROPERTY_OWNER.CONTROL, 'precogly:control-nature', countermeasure.controlNature || undefined),
    known(PROPERTY_OWNER.CONTROL, 'precogly:mitigates', scenarioRefs.length > 0 ? scenarioRefs : undefined),
  ]
  return withProperties(control, mergeProperties(keptProperties(passthrough), properties))
}

function trustLevelName(level: number): string {
  if (level <= 25) return 'untrusted'
  if (level <= 50) return 'semi-trusted'
  if (level <= 75) return 'trusted'
  return 'highly-trusted'
}

function buildTrustBoundaries(
  edges: readonly DiagramEdge[],
  nodesById: Map<string, DiagramNode>,
  threats: readonly GuestThreat[],
  countermeasures: readonly GuestCountermeasure[],
  refs: ElementRefs,
  kept: GuestKeptContent,
  book: RefBook
): CycloneDxTrustBoundary[] {
  const generated = new Map<string, CycloneDxTrustBoundary>()
  for (const edge of edges) {
    if (edge.type !== 'trustBoundary') continue
    const boundaryRef = refs.edgeRefs.get(edge.id)
    if (!boundaryRef || !refs.nodeRefs.has(edge.source) || !refs.nodeRefs.has(edge.target)) continue
    const data = edgeData(edge)
    const keptEntry = kept.trustBoundaries[boundaryRef]
    const customType = data.boundaryType === undefined && isObject(kept.entries[boundaryRef]?.__customType)
    if (customType || getBoundaryType(data) !== 'trust') continue
    const entry: CycloneDxTrustBoundary = {
      ...(keptEntry ? passthroughKeys(keptEntry, ['bom-ref', 'boundary', 'name', 'trustLevel', 'threatsAtBoundary', 'controlsAtBoundary']) : {}),
      'bom-ref': keptEntry && typeof keptEntry['bom-ref'] === 'string' ? keptEntry['bom-ref'] : book.claim(undefined, `trustboundary-${edge.id}`),
      boundary: boundaryRef,
    }
    const label = asString(data.label)
    if (label) entry.name = label
    const levelA = getTrustLevel(nodeData(nodesById.get(edge.source)!))
    const levelB = getTrustLevel(nodeData(nodesById.get(edge.target)!))
    if (levelA !== null && levelB !== null) entry.trustLevel = trustLevelName(Math.min(levelA, levelB))
    const threatRefs = threats
      .filter((threat) => threat.targets.some((target) => target.type === 'boundary' && target.id === edge.id))
      .map((threat) => refs.threatRefs.get(threat.id)!)
    if (threatRefs.length > 0) entry.threatsAtBoundary = threatRefs
    const controlRefs = countermeasures
      .filter((countermeasure) => countermeasure.targets.some((target) => target.type === 'boundary' && target.id === edge.id))
      .map((countermeasure) => refs.countermeasureRefs.get(countermeasure.id)!)
    if (controlRefs.length > 0) entry.controlsAtBoundary = controlRefs
    generated.set(entry['bom-ref'], entry)
  }
  const hidden = Object.entries(kept.trustBoundaries)
    .filter(([boundaryRef]) => ![...refs.edgeRefs.values()].includes(boundaryRef))
    .map(([, entry]) => entry)
  return orderSection(kept, 'trustBoundaries', generated, hidden) as CycloneDxTrustBoundary[]
}

/** Drop refs in kept content that point at nothing any more (plan 9.2, K2). */
function repairStaleRefs(document: CycloneDxDocument, warnings: string[]): void {
  const refs = collectRefs(document, new Set<string>())
  const resolves = (value: unknown) => typeof value !== 'string' || value === '' || value.startsWith('urn:cdx:') || refs.has(value)
  const describe = (node: JsonObject) => asString(node.name) || asString(node['bom-ref']) || 'an entry'

  const repairList = (list: JsonObject[], required: (entry: JsonObject) => string[], context: string) => {
    for (let index = list.length - 1; index >= 0; index -= 1) {
      const entry = list[index]
      if (!isObject(entry)) continue
      walk(entry)
      const missing = required(entry).filter((key) => entry[key] !== undefined && !resolves(entry[key]))
      const zones = Array.isArray(entry.zones) ? entry.zones.length : null
      if (missing.length > 0 || (context === 'boundaries' && zones !== null && zones < 2)) {
        warnings.push(`${context}: ${describe(entry)} was left out of the file because what it refers to is gone.`)
        list.splice(index, 1)
      }
    }
  }

  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (!isObject(node)) return
    for (const [key, value] of Object.entries(node)) {
      if (REF_KEY_SET.has(key)) {
        if (Array.isArray(value)) {
          const kept = value.filter((item) => !(typeof item === 'string') || resolves(item))
          if (kept.length !== value.length) {
            warnings.push(`${describe(node)}: ${value.length - kept.length} reference(s) in ${key} pointed at nothing and were dropped.`)
            if (kept.length > 0) node[key] = kept
            else delete node[key]
          }
          walk(kept)
          continue
        }
        if (typeof value === 'string' && !resolves(value) && !['source', 'destination', 'boundary', 'ref'].includes(key)) {
          warnings.push(`${describe(node)}: ${key} pointed at nothing and was dropped.`)
          delete node[key]
          continue
        }
      }
      walk(value)
    }
  }

  for (const blueprint of document.blueprints ?? []) {
    if (Array.isArray(blueprint.flows)) repairList(blueprint.flows as JsonObject[], () => ['source', 'destination'], 'flows')
    if (Array.isArray(blueprint.boundaries)) repairList(blueprint.boundaries as JsonObject[], () => [], 'boundaries')
    if (Array.isArray(blueprint.relationships)) repairList(blueprint.relationships as JsonObject[], () => ['ref'], 'relationships')
  }
  if (Array.isArray(document.threats?.trustBoundaries)) {
    repairList(document.threats.trustBoundaries as JsonObject[], () => ['boundary'], 'trust boundaries')
  }
  walk(document)
}

function sessionPropertyValue(context: GuestSystemContext): string | undefined {
  const { facilitator, participants, meetingDate } = context.session
  if (!facilitator && participants.length === 0 && !meetingDate) return undefined
  return stableStringify({ facilitator, participants, meetingDate })
}

export function buildGuestDocument(input: GuestExportInput): GuestExportResult {
  const { title, nodes, edges, threats, countermeasures, systemContext, documentState } = input
  const kept = documentState.kept
  const warnings: string[] = []
  const nodesById = new Map(nodes.map((node) => [node.id, node]))

  const reserved = new Set<string>()
  collectRefs(kept.document, reserved)
  collectRefs(kept.metadata, reserved)
  collectRefs(kept.blueprint, reserved)
  collectRefs(kept.extraBlueprints, reserved)
  collectRefs(kept.hiddenEntries, reserved)
  collectRefs(kept.threatsSection, reserved)
  collectRefs(kept.metadataComponent, reserved)
  const book = new RefBook(reserved)

  const refs: ElementRefs = {
    nodeRefs: new Map(),
    edgeRefs: new Map(),
    threatRefs: new Map(),
    countermeasureRefs: new Map(),
    dataSetRefs: new Map(),
    assumptionRefs: new Map(),
    systemRef: '',
  }
  const keptComponentRef = kept.metadataComponent && typeof kept.metadataComponent['bom-ref'] === 'string' ? kept.metadataComponent['bom-ref'] : undefined
  refs.systemRef = book.claim(keptComponentRef, 'system-model-1')
  for (const node of nodes) {
    const targetType = targetTypeForNode(node)
    if (!targetType) continue
    const prefix = node.type === 'trustZone' ? 'zone' : node.type === 'datastore' ? 'datastore' : 'asset'
    refs.nodeRefs.set(node.id, book.claim(storedRef(node.data), `${prefix}-${node.id}`))
  }
  for (const edge of edges) {
    const targetType = targetTypeForEdge(edge)
    if (!targetType) continue
    refs.edgeRefs.set(edge.id, book.claim(storedRef(edge.data), `${targetType}-${edge.id}`))
  }
  for (const threat of threats) refs.threatRefs.set(threat.id, book.claim(threat.bomRef, `scenario-${threat.id}`))
  for (const countermeasure of countermeasures) {
    refs.countermeasureRefs.set(countermeasure.id, book.claim(countermeasure.bomRef, `control-${countermeasure.id}`))
  }
  for (const asset of systemContext.dataAssets) refs.dataSetRefs.set(asset.id, book.claim(asset.bomRef, `dataset-${asset.id}`))
  for (const assumption of systemContext.assumptions) {
    refs.assumptionRefs.set(assumption.id, book.claim(assumption.bomRef, `assumption-${assumption.id}`))
  }

  // --- The first blueprint ---
  const zones = new Map<string, CycloneDxZone>()
  const assets = new Map<string, CycloneDxAsset>()
  const dataStores = new Map<string, CycloneDxDataStore>()
  for (const node of nodes) {
    const ref = refs.nodeRefs.get(node.id)
    if (!ref) continue
    if (node.type === 'trustZone') zones.set(ref, buildZone(node, nodesById, refs, kept))
    else if (node.type === 'datastore') dataStores.set(ref, buildDataStore(node, nodesById, refs, kept))
    else assets.set(ref, buildAsset(node, nodesById, refs, kept))
  }
  const flows = new Map<string, CycloneDxFlow>()
  const boundaries = new Map<string, CycloneDxBoundary>()
  for (const edge of edges) {
    const ref = refs.edgeRefs.get(edge.id)
    if (!ref) continue
    if (edge.type === 'dataFlow') {
      const flow = buildFlow(edge, nodesById, refs, kept)
      if (flow) flows.set(ref, flow)
      else warnings.push(`Flow ${asString(edgeData(edge).label) || edge.id} was left out: one of its ends is not a component.`)
    } else if (edge.type === 'trustBoundary') {
      const boundary = buildBoundary(edge, refs, kept)
      if (boundary) boundaries.set(ref, boundary)
      else warnings.push(`Boundary ${asString(edgeData(edge).label) || edge.id} was left out: one of its ends is not a zone.`)
    }
  }
  const dataSets = new Map<string, CycloneDxDataSet>()
  for (const asset of systemContext.dataAssets) dataSets.set(refs.dataSetRefs.get(asset.id)!, buildDataSet(asset, refs))
  const assumptions = new Map<string, CycloneDxAssumption>()
  for (const assumption of systemContext.assumptions) {
    assumptions.set(refs.assumptionRefs.get(assumption.id)!, buildAssumption(assumption, refs))
  }

  const canvas: JsonObject = { ...deepClone(kept.canvasExtras) }
  if (input.notationStyle) canvas.notation_style = input.notationStyle
  canvas.nodes = nodes.map((node) => nodeForFile(node, refs.nodeRefs.get(node.id) ?? null))
  canvas.edges = edges.map((edge) => edgeForFile(edge, refs.edgeRefs.get(edge.id) ?? null))
  const attachment = { mediaType: PRECOGLY_DFD_MEDIA_TYPE, encoding: 'base64' as const, content: encodeCanvasContent(canvas) }
  const visualization: CycloneDxVisualization = kept.visualization
    ? { ...(deepClone(kept.visualization) as JsonObject), attachment } as CycloneDxVisualization
    : {
        'bom-ref': book.claim(undefined, 'visualization-1'),
        name: title,
        type: { type: 'data-flow' },
        attachment,
        properties: mergeProperties(undefined, [
          known(PROPERTY_OWNER.VISUALIZATION, 'precogly:diagram-type', 'level1'),
          known(PROPERTY_OWNER.VISUALIZATION, 'precogly:primary', true),
        ]),
      }
  const visualizations = new Map<string, CycloneDxVisualization>()
  visualizations.set(asString(visualization['bom-ref']) || '__guest', visualization)

  const blueprint: CycloneDxBlueprint = {
    'bom-ref': kept.blueprintRef ?? book.claim(undefined, 'blueprint-1'),
    name: title,
    modelTypes: (kept.blueprintModelTypes && kept.blueprintModelTypes.length > 0 ? deepClone(kept.blueprintModelTypes) : ['data-flow']) as CycloneDxTypeValue[],
  }
  if (systemContext.systemInfo.description) blueprint.description = systemContext.systemInfo.description
  const scope = buildScope(systemContext.outOfScopeItems, nodes, refs, kept, title)
  if (scope) blueprint.scope = scope as CycloneDxBlueprint['scope']
  const sections: [string, Map<string, JsonObject>][] = [
    ['assets', assets],
    ['dataStores', dataStores],
    ['dataSets', dataSets],
    ['zones', zones],
    ['boundaries', boundaries],
    ['flows', flows],
    ['visualizations', visualizations],
    ['assumptions', assumptions],
  ]
  for (const [section, generated] of sections) {
    const ordered = orderSection(kept, section, generated, kept.hiddenEntries[section] ?? [])
    if (ordered.length > 0) blueprint[section] = ordered
  }
  Object.assign(blueprint, deepClone(kept.blueprint))

  // --- Threats and controls ---
  const { entries: abstractThreats, byThreat } = buildAbstractThreats(threats, countermeasures, refs, kept)
  const scenarios = threats.map((threat) => buildScenario(threat, countermeasures, refs, byThreat.get(threat.id)!))
  const controls = countermeasures.map((countermeasure) => buildControl(countermeasure, refs))
  const trustBoundaries = buildTrustBoundaries(edges, nodesById, threats, countermeasures, refs, kept, book)

  const threatsSection: JsonObject = {}
  if (abstractThreats.length > 0) threatsSection.threats = abstractThreats
  if (scenarios.length > 0) threatsSection.scenarios = scenarios
  if (trustBoundaries.length > 0) threatsSection.trustBoundaries = trustBoundaries
  Object.assign(threatsSection, deepClone(kept.threatsSection))

  // --- Metadata ---
  const component: CycloneDxMetadataComponent = kept.metadataComponent
    ? (deepClone(kept.metadataComponent) as CycloneDxMetadataComponent)
    : { type: 'application', 'bom-ref': refs.systemRef, name: title }
  component['bom-ref'] = refs.systemRef
  if (!kept.metadataComponent) component.name = title
  const componentProperties = mergeProperties(keptProperties(component), [
    known(PROPERTY_OWNER.SYSTEM, 'precogly:criticality', CRITICALITY_TO_SPEC[systemContext.systemInfo.criticality]),
  ])
  withProperties(component, componentProperties)
  const metadata: JsonObject = {
    timestamp: new Date().toISOString(),
    tools: { components: [{ type: 'application', name: GUEST_TOOL_NAME, version: GUEST_TOOL_VERSION }] },
    ...deepClone(kept.metadata),
    component,
  }

  const documentProperties = mergeProperties(kept.documentProperties, [
    known(PROPERTY_OWNER.DOCUMENT, 'precogly:next-threat-number', documentState.nextThreatNumber),
    known(PROPERTY_OWNER.DOCUMENT, 'precogly:next-countermeasure-number', documentState.nextCountermeasureNumber),
    { name: GUEST_SESSION_PROPERTY, value: sessionPropertyValue(systemContext), valueType: 'string' },
  ])

  const document: CycloneDxDocument = {
    specFormat: 'CycloneDX',
    specVersion: '2.0',
    serialNumber: documentState.serialNumber,
    metadata,
    blueprints: [blueprint, ...(deepClone(kept.extraBlueprints) as CycloneDxBlueprint[])],
  }
  if (Object.keys(threatsSection).length > 0) document.threats = threatsSection
  if (controls.length > 0) document.controls = controls
  Object.assign(document, deepClone(kept.document))
  document.properties = documentProperties

  repairStaleRefs(document, warnings)

  const digest = contentDigest(document)
  const version = documentState.exportDigest !== null && documentState.exportDigest !== digest
    ? documentState.version + 1
    : documentState.version
  document.version = version
  return { document, json: JSON.stringify(document, null, 2), version, digest, warnings }
}

/** The JSON text to write. See `buildGuestDocument` for the version and digest. */
export function serializeGuestToCycloneDx(input: GuestExportInput): string {
  return buildGuestDocument(input).json
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

export interface DeserializedFile {
  title: string
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  threats: GuestThreat[]
  countermeasures: GuestCountermeasure[]
  systemContext: GuestSystemContext
  notationStyle?: DFDNotationStyle
  documentState: GuestDocumentState
  /** Everything that could not be read as it was. Shown in the UI, never logged. */
  warnings: string[]
  /** Blueprints after the first (G8). */
  hiddenBlueprintCount: number
  /** First-blueprint elements that are not on the diagram and travel as they are. */
  hiddenElementCount: number
}

function emptySystemContext(): GuestSystemContext {
  return {
    session: { facilitator: '', participants: [], meetingDate: '' },
    systemInfo: { description: '', criticality: 'medium' },
    dataAssets: [],
    assumptions: [],
    outOfScopeItems: [],
  }
}

function entryLabel(entry: JsonObject, fallback: string): string {
  return asString(entry.name) || asString(entry['bom-ref']) || fallback
}

/**
 * Write a blueprint value onto canvas data without adding a key the canvas
 * never had for a default value, so a canvas that said nothing still says
 * nothing after a round trip.
 */
function applyCanvasValue(data: JsonObject, key: string, value: unknown, defaultValue: unknown): void {
  if (value === defaultValue && !(key in data)) return
  if (value === undefined) delete data[key]
  else data[key] = value
}

interface ElementIndex {
  /** bom-ref -> canvas id */
  nodes: Map<string, string>
  edges: Map<string, string>
}

class Importer {
  readonly document: JsonObject
  readonly warnings: string[] = []
  readonly kept = emptyKeptContent()
  nodes: DiagramNode[] = []
  edges: DiagramEdge[] = []
  readonly index: ElementIndex = { nodes: new Map(), edges: new Map() }
  readonly nodeTypeByRef = new Map<string, DiagramNode['type']>()
  systemRef = ''
  hiddenElementCount = 0
  private readonly extraBlueprintRefs = new Set<string>()
  private generatedLayout = false

  constructor(document: JsonObject) {
    this.document = document
  }

  warn(message: string): void {
    this.warnings.push(message)
  }

  // -- document level ---------------------------------------------------

  readDocumentLevel(): void {
    for (const [key, value] of Object.entries(this.document)) {
      if (!DOCUMENT_KNOWN_KEYS.has(key)) this.kept.document[key] = deepClone(value)
    }
    const metadata = isObject(this.document.metadata) ? this.document.metadata : {}
    for (const [key, value] of Object.entries(metadata)) {
      if (!METADATA_KNOWN_KEYS.has(key)) this.kept.metadata[key] = deepClone(value)
    }
    if (isObject(metadata.component)) {
      this.kept.metadataComponent = deepClone(metadata.component)
      this.systemRef = asString(metadata.component['bom-ref'])
    }
    this.kept.documentProperties = Array.isArray(this.document.properties)
      ? (this.document.properties as unknown[]).filter((item): item is CycloneDxProperty => isObject(item) && typeof item.name === 'string').map((item) => deepClone(item))
      : []
    const threatsSection = isObject(this.document.threats) ? this.document.threats : null
    if (this.document.threats !== undefined && threatsSection === null) {
      this.warn("The 'threats' section is not an object and was skipped.")
    }
    for (const [key, value] of Object.entries(threatsSection ?? {})) {
      if (!THREATS_SECTION_KNOWN_KEYS.has(key)) this.kept.threatsSection[key] = deepClone(value)
    }
  }

  // -- blueprint ----------------------------------------------------------

  readBlueprint(): CycloneDxBlueprint | null {
    const blueprints = Array.isArray(this.document.blueprints) ? this.document.blueprints : []
    if (!Array.isArray(this.document.blueprints) || blueprints.length === 0) {
      this.warn('The file has no blueprints; the diagram is empty.')
      return null
    }
    const [first, ...rest] = blueprints
    this.kept.extraBlueprints = deepClone(rest)
    collectRefs(rest, this.extraBlueprintRefs)
    if (!isObject(first)) {
      this.warn('The first blueprint is not an object; the diagram is empty.')
      return null
    }
    for (const [key, value] of Object.entries(first)) {
      if (!BLUEPRINT_KNOWN_KEYS.has(key)) this.kept.blueprint[key] = deepClone(value)
    }
    this.kept.blueprintRef = asString(first['bom-ref']) || null
    this.kept.blueprintModelTypes = Array.isArray(first.modelTypes) ? deepClone(first.modelTypes) : null
    return first as CycloneDxBlueprint
  }

  private entries(blueprint: CycloneDxBlueprint, section: string): JsonObject[] {
    const value = blueprint[section]
    if (value === undefined) return []
    if (!Array.isArray(value)) {
      this.warn(`Blueprint section '${section}' is not a list and was skipped.`)
      return []
    }
    const entries: JsonObject[] = []
    value.forEach((item, position) => {
      if (isObject(item)) entries.push(item)
      else this.warn(`Entry ${position} of '${section}' is not an object and was skipped.`)
    })
    this.kept.entryOrder[section] = entries.map((entry) => asString(entry['bom-ref'])).filter((ref) => ref !== '')
    return entries
  }

  private keepEntry(ref: string, entry: JsonObject, section: string, extra: JsonObject = {}): void {
    const knownKeys = ENTRY_KNOWN_KEYS[section]
    const kept: JsonObject = {}
    for (const [key, value] of Object.entries(entry)) {
      if (!knownKeys.has(key)) kept[key] = deepClone(value)
    }
    if (Array.isArray(entry.properties)) kept.properties = deepClone(entry.properties)
    Object.assign(kept, extra)
    this.kept.entries[ref] = kept
  }

  private hide(section: string, entry: JsonObject): void {
    ;(this.kept.hiddenEntries[section] ??= []).push(deepClone(entry))
    this.hiddenElementCount += 1
  }

  readCanvas(blueprint: CycloneDxBlueprint): void {
    const visualizations = this.entries(blueprint, 'visualizations')
    let canvas: JsonObject | null = null
    for (const visualization of visualizations) {
      const attachment = isObject(visualization.attachment) ? visualization.attachment : null
      if (canvas === null && attachment?.mediaType === PRECOGLY_DFD_MEDIA_TYPE) {
        const decoded = decodeCanvasContent(attachment.content, attachment.encoding)
        if (decoded === null) {
          this.warn(`Visualization '${entryLabel(visualization, 'diagram')}' carries a Precogly canvas that could not be decoded; a layout was generated instead.`)
          continue
        }
        canvas = decoded
        const kept: JsonObject = {}
        for (const [key, value] of Object.entries(visualization)) {
          if (key !== 'attachment') kept[key] = deepClone(value)
        }
        this.kept.visualization = kept
        continue
      }
      ;(this.kept.hiddenEntries.visualizations ??= []).push(deepClone(visualization))
    }
    if (canvas === null) {
      this.generatedLayout = true
      return
    }
    const camel = keysToCamelCase(canvas) as JsonObject
    for (const [key, value] of Object.entries(canvas)) {
      if (key !== 'nodes' && key !== 'edges') this.kept.canvasExtras[key] = deepClone(value)
    }
    this.nodes = (Array.isArray(camel.nodes) ? camel.nodes : []).filter((node): node is DiagramNode => isObject(node) && typeof node.id === 'string')
    this.edges = (Array.isArray(camel.edges) ? camel.edges : []).filter((edge): edge is DiagramEdge => isObject(edge) && typeof edge.id === 'string')
    for (const node of this.nodes) {
      node.data = (isObject(node.data) ? node.data : { label: '' }) as DiagramNode['data']
      const ref = storedRef(node.data)
      if (ref && targetTypeForNode(node)) this.index.nodes.set(ref, node.id)
    }
    for (const edge of this.edges) {
      edge.data = (isObject(edge.data) ? edge.data : {}) as DiagramEdge['data']
      const ref = storedRef(edge.data)
      if (ref && targetTypeForEdge(edge)) this.index.edges.set(ref, edge.id)
    }
  }

  /** A canvas node without a bom-ref may still match an entry by name (consumed once). */
  private matchNode(entry: JsonObject, expectedTypes: readonly string[]): DiagramNode | null {
    const ref = asString(entry['bom-ref'])
    const byRef = ref ? this.index.nodes.get(ref) : undefined
    if (byRef) return this.nodes.find((node) => node.id === byRef) ?? null
    if (this.generatedLayout) return null
    const name = asString(entry.name)
    const claimed = new Set(this.index.nodes.values())
    const match = this.nodes.find(
      (node) => !claimed.has(node.id) && expectedTypes.includes(node.type ?? '') && nodeLabel(node, '') === name && storedRef(node.data) === undefined
    )
    if (match && ref) this.index.nodes.set(ref, match.id)
    return match ?? null
  }

  private matchEdge(entry: JsonObject, expectedType: string, endRefs: [string, string]): DiagramEdge | null {
    const ref = asString(entry['bom-ref'])
    const byRef = ref ? this.index.edges.get(ref) : undefined
    if (byRef) return this.edges.find((edge) => edge.id === byRef) ?? null
    if (this.generatedLayout) return null
    const source = this.index.nodes.get(endRefs[0])
    const target = this.index.nodes.get(endRefs[1])
    if (!source || !target) return null
    const claimed = new Set(this.index.edges.values())
    const candidates = this.edges.filter(
      (edge) => !claimed.has(edge.id) && edge.type === expectedType && storedRef(edge.data) === undefined
        && ((edge.source === source && edge.target === target) || (expectedType === 'trustBoundary' && edge.source === target && edge.target === source))
    )
    const match = candidates.find((edge) => asString(edgeData(edge).label) === asString(entry.name)) ?? candidates[0]
    if (match && ref) this.index.edges.set(ref, match.id)
    return match ?? null
  }

  private reconcileLabel(data: JsonObject, name: string, what: string): void {
    if (!name) return
    const current = asString(data.label)
    if (current && current !== name) {
      this.warn(`Diagram ${what} '${current}' renamed to '${name}' to match the blueprint.`)
    }
    data.label = name
  }

  private specType(raw: unknown, allowed: readonly string[], label: string, what: string): { value: string | undefined; custom: JsonObject | null } {
    const name = typeName(raw)
    if (!name) return { value: undefined, custom: null }
    if (allowed.includes(name)) return { value: name, custom: null }
    this.warn(`${what} '${label}': type '${name}' is not a CycloneDX value; shown with the default type and kept for the file.`)
    return { value: undefined, custom: isObject(raw) ? deepClone(raw) : { name } }
  }

  private newNodeId(prefix: string): string {
    return `${prefix}-${uuid().slice(0, 8)}`
  }

  readZones(blueprint: CycloneDxBlueprint): void {
    const zones = this.entries(blueprint, 'zones')
    const pending: { node: DiagramNode; parentRef: string }[] = []
    zones.forEach((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const label = entryLabel(entry, `zone ${position}`)
      let node = this.matchNode(entry, ['trustZone'])
      if (!node && this.generatedLayout) {
        node = {
          id: this.newNodeId('zone'),
          type: 'trustZone',
          position: { x: 50 + position * 450, y: 50 },
          data: { label, zoneColor: '#22c55e' },
          style: { width: 400, height: 300 },
        } as DiagramNode
        this.nodes.push(node)
        if (ref) this.index.nodes.set(ref, node.id)
      }
      if (!node) {
        this.hide('zones', entry)
        return
      }
      const data = nodeData(node)
      if (ref) data.bomRef = ref
      this.reconcileLabel(data, asString(entry.name), 'zone')
      if (asString(entry.description)) data.description = entry.description
      const { value, custom } = this.specType(entry.type, ZONE_TYPES, label, 'Zone')
      applyCanvasValue(data, 'zoneType', value, 'trust')
      const properties = readProperties(entry.properties, PROPERTY_OWNER.ZONE)
      const trustLevel = properties.get('precogly:trust-level')
      applyCanvasValue(data, 'trustLevel', typeof trustLevel === 'number' && trustLevel >= 0 && trustLevel <= 100 ? trustLevel : undefined, undefined)
      if (ref) {
        this.nodeTypeByRef.set(ref, 'trustZone')
        this.keepEntry(ref, entry, 'zones', custom ? { __customType: custom } : {})
      }
      if (asString(entry.parent)) pending.push({ node, parentRef: asString(entry.parent) })
    })
    for (const { node, parentRef } of pending) {
      const parentId = this.index.nodes.get(parentRef)
      if (!parentId) {
        this.warn(`Zone '${nodeLabel(node, node.id)}': parent '${parentRef}' is not a zone on the diagram; shown without a parent.`)
        continue
      }
      if (this.generatedLayout) {
        node.parentId = parentId
        node.position = { x: 30, y: 60 }
      }
    }
  }

  readAssets(blueprint: CycloneDxBlueprint, section: 'assets' | 'dataStores'): void {
    const entries = this.entries(blueprint, section)
    const zoneChildCount = new Map<string, number>()
    entries.forEach((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const label = entryLabel(entry, `${section === 'assets' ? 'asset' : 'data store'} ${position}`)
      const properties = readProperties(entry.properties, section === 'assets' ? PROPERTY_OWNER.ASSET : PROPERTY_OWNER.DATA_STORE)
      const assetProperties = readProperties(entry.properties, PROPERTY_OWNER.ASSET)
      const nodeType = section === 'dataStores' ? 'datastore' : this.nodeTypeForAsset(entry, assetProperties)
      let node = this.matchNode(entry, section === 'dataStores' ? ['datastore'] : ['process', 'humanActor', 'systemActor', 'systemScope'])
      if (!node && this.generatedLayout) {
        const zoneId = asString(entry.zone) ? this.index.nodes.get(asString(entry.zone)) : undefined
        const childIndex = zoneChildCount.get(zoneId ?? '') ?? 0
        zoneChildCount.set(zoneId ?? '', childIndex + 1)
        node = {
          id: this.newNodeId(nodeType),
          type: nodeType,
          position: zoneId
            ? { x: 30 + (childIndex % 2) * 180, y: 60 + Math.floor(childIndex / 2) * 120 }
            : { x: 50 + (childIndex % 4) * 220, y: 450 + Math.floor(childIndex / 4) * 140 },
          ...(zoneId ? { parentId: zoneId } : {}),
          data: { label },
        } as DiagramNode
        this.nodes.push(node)
        if (ref) this.index.nodes.set(ref, node.id)
      }
      if (!node) {
        this.hide(section, entry)
        return
      }
      const data = nodeData(node)
      if (ref) data.bomRef = ref
      this.reconcileLabel(data, asString(entry.name), 'element')
      if (asString(entry.description)) data.description = entry.description
      const extra: JsonObject = {}
      if (section === 'assets') {
        const { value, custom } = this.specType(entry.type, ASSET_TYPES, label, 'Asset')
        applyCanvasValue(data, 'kind', value, kindForNodeType(node.type))
        if (custom) extra.__customType = custom
        const actorType = asString(assetProperties.get('precogly:actor-type'))
        if (actorType && node.type === 'humanActor') data.actorType = actorType
        if (actorType && node.type === 'systemActor') data.systemType = actorType
      } else {
        const own = asString(properties.get('precogly:data-store-type'))
        const spec = typeName(entry.type)
        if (own) data.dataStoreType = own
        else if ((DATA_STORE_TYPES as readonly string[]).includes(spec)) data.dataStoreType = SPEC_TO_DATA_STORE_TYPE[spec] ?? spec
        else {
          applyCanvasValue(data, 'dataStoreType', undefined, undefined)
          if (spec && spec !== 'unspecified') extra.__customType = isObject(entry.type) ? deepClone(entry.type) : { name: spec }
        }
      }
      // The canvas nodes draw the three editor levels; any other value the
      // file carries stays with the entry and is written back as it came.
      const sensitivity = asString(assetProperties.get('precogly:data-sensitivity'))
      if (sensitivity && sensitivity in DATA_SENSITIVITY_CONFIG) data.dataSensitivity = sensitivity
      else if (sensitivity) extra.__dataSensitivity = sensitivity
      if (ref) {
        this.nodeTypeByRef.set(ref, node.type)
        this.keepEntry(ref, entry, section, extra)
      }
    })
  }

  private nodeTypeForAsset(entry: JsonObject, properties: Map<string, unknown>): DiagramNode['type'] {
    const category = asString(properties.get('precogly:category'))
    if (category === 'external_human_actor') return 'humanActor'
    if (category === 'external_system_actor') return 'systemActor'
    if (category === 'process') return 'process'
    const type = typeName(entry.type)
    if (type === 'actor') return 'humanActor'
    if (type === 'agent' || type === 'system' || type === 'subsystem') return 'systemActor'
    return 'process'
  }

  readFlows(blueprint: CycloneDxBlueprint): void {
    const flows = this.entries(blueprint, 'flows')
    flows.forEach((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const label = entryLabel(entry, `flow ${position}`)
      const sourceRef = asString(entry.source)
      const destinationRef = asString(entry.destination)
      let edge = this.matchEdge(entry, 'dataFlow', [sourceRef, destinationRef])
      const sourceId = this.index.nodes.get(sourceRef)
      const targetId = this.index.nodes.get(destinationRef)
      if (!edge && this.generatedLayout && sourceId && targetId) {
        edge = { id: this.newNodeId('flow'), type: 'dataFlow', source: sourceId, target: targetId, animated: true, data: {} } as DiagramEdge
        this.edges.push(edge)
        if (ref) this.index.edges.set(ref, edge.id)
      }
      if (!edge) {
        this.hide('flows', entry)
        return
      }
      const data = edgeData(edge)
      if (ref) data.bomRef = ref
      const sourceNode = this.nodes.find((node) => node.id === edge!.source)
      const targetNode = this.nodes.find((node) => node.id === edge!.target)
      const fallbackName = `${sourceNode ? nodeLabel(sourceNode, '') : ''} to ${targetNode ? nodeLabel(targetNode, '') : ''}`
      const name = asString(entry.name)
      if (name && name !== fallbackName) data.label = name
      else if (asString(data.label)) data.label = ''
      if (asString(entry.description)) data.description = entry.description
      const { value, custom } = this.specType(entry.type, FLOW_TYPES, label, 'Flow')
      applyCanvasValue(data, 'flowType', value, 'data')
      const protocols = stringList(entry.protocols)
      applyCanvasValue(data, 'protocol', protocols[0], undefined)
      applyCanvasValue(data, 'encrypted', entry.encrypted === true, false)
      const authentication = Array.isArray(entry.authentication) ? entry.authentication.map(typeName).filter((item) => item !== '') : []
      if (authentication.includes('none') && authentication.length > 1) {
        this.warn(`Flow '${label}': authentication mixes 'none' with other values; shown as not recorded.`)
        data.authentication = []
      } else if (authentication.length > 0 || 'authentication' in data || 'authenticated' in data) {
        data.authentication = authentication
      }
      delete data.authenticated
      const properties = readProperties(entry.properties, PROPERTY_OWNER.FLOW)
      const port = properties.get('precogly:port')
      applyCanvasValue(data, 'port', typeof port === 'number' ? port : undefined, undefined)
      applyCanvasValue(data, 'hasSensitiveData', properties.get('precogly:has-sensitive-data') === true, false)
      const classification = jsonPropertyItems(properties, 'precogly:data-classification').filter((item): item is string => typeof item === 'string')
      applyCanvasValue(data, 'dataClassification', classification.length > 0 ? classification : undefined, undefined)
      if (ref) this.keepEntry(ref, entry, 'flows', custom ? { __customType: custom } : {})
    })
  }

  readBoundaries(blueprint: CycloneDxBlueprint): void {
    const boundaries = this.entries(blueprint, 'boundaries')
    boundaries.forEach((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const label = entryLabel(entry, `boundary ${position}`)
      const zoneRefs = stringList(entry.zones)
      let edge = this.matchEdge(entry, 'trustBoundary', [zoneRefs[0] ?? '', zoneRefs[1] ?? ''])
      const sourceId = zoneRefs[0] ? this.index.nodes.get(zoneRefs[0]) : undefined
      const targetId = zoneRefs[1] ? this.index.nodes.get(zoneRefs[1]) : undefined
      if (!edge && this.generatedLayout && sourceId && targetId) {
        edge = { id: this.newNodeId('boundary'), type: 'trustBoundary', source: sourceId, target: targetId, data: {} } as DiagramEdge
        this.edges.push(edge)
        if (ref) this.index.edges.set(ref, edge.id)
      }
      if (!edge) {
        this.hide('boundaries', entry)
        return
      }
      if (zoneRefs.length > 2) {
        this.warn(`Boundary '${label}' joins ${zoneRefs.length} zones; the first two are shown and the rest are kept for the file.`)
      }
      const data = edgeData(edge)
      if (ref) data.bomRef = ref
      if (asString(entry.name)) data.label = entry.name
      const { value, custom } = this.specType(entry.type, BOUNDARY_TYPES, label, 'Boundary')
      applyCanvasValue(data, 'boundaryType', value, 'trust')
      const requirements = isObject(entry.crossingRequirements) ? entry.crossingRequirements : {}
      const leftoverRequirements: JsonObject = {}
      for (const [key, raw] of Object.entries(requirements)) {
        if (key === 'authentication' || key === 'authorization') {
          const values = Array.isArray(raw) ? raw.map(typeName).filter((item) => item !== '') : []
          if (values.includes('none') && values.length > 1) {
            this.warn(`Boundary '${label}': ${key} mixes 'none' with other values; shown as not recorded.`)
            data[key === 'authentication' ? 'authenticationMethods' : 'accessControlMethods'] = []
          } else {
            data[key === 'authentication' ? 'authenticationMethods' : 'accessControlMethods'] = values
          }
        } else if (key === 'dataValidation' || key === 'logging' || key === 'monitoring') {
          applyCanvasValue(data, key, raw === true, false)
        } else if (key === 'rateLimit') {
          applyCanvasValue(data, 'rateLimit', asString(raw) || undefined, undefined)
        } else {
          leftoverRequirements[key] = deepClone(raw)
        }
      }
      const session = isObject(entry.sessionManagement) ? entry.sessionManagement : {}
      const leftoverSession: JsonObject = {}
      for (const [key, raw] of Object.entries(session)) {
        const canvasKey = SESSION_SPEC_TO_CANVAS[key]
        if (canvasKey) data[canvasKey] = raw
        else leftoverSession[key] = deepClone(raw)
      }
      if (ref) {
        this.keepEntry(ref, entry, 'boundaries', {
          ...(custom ? { __customType: custom } : {}),
          ...(Object.keys(leftoverRequirements).length > 0 ? { __crossingRequirements: leftoverRequirements } : {}),
          ...(Object.keys(leftoverSession).length > 0 ? { __sessionManagement: leftoverSession } : {}),
          ...(zoneRefs.length > 2 ? { __extraZones: zoneRefs.slice(2) } : {}),
        })
      }
    })
  }

  readDataSets(blueprint: CycloneDxBlueprint): GuestDataAsset[] {
    return this.entries(blueprint, 'dataSets').map((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const name = asString(entry.name)
      if (!name) this.warn(`Data set ${ref || position} has no name.`)
      const profiles = Array.isArray(entry.dataProfiles) ? entry.dataProfiles : []
      const firstProfile = isObject(profiles[0]) ? profiles[0] : null
      const classification = firstProfile ? typeName(firstProfile.classification) : ''
      const properties = readProperties(entry.properties, PROPERTY_OWNER.DATA_SET)
      const level = (key: string): 'low' | 'medium' | 'high' => {
        const value = asString(properties.get(key))
        return value === 'low' || value === 'high' ? value : 'medium'
      }
      const passthrough: JsonObject = {}
      for (const [key, value] of Object.entries(entry)) {
        if (!ENTRY_KNOWN_KEYS.dataSets.has(key)) passthrough[key] = deepClone(value)
      }
      if (Array.isArray(entry.properties)) passthrough.properties = deepClone(entry.properties)
      if (firstProfile) passthrough.__profile = deepClone(firstProfile)
      if (profiles.length > 1) passthrough.__extraProfiles = deepClone(profiles.slice(1))
      return {
        id: ref || `dataset-${uuid()}`,
        name: name || `Data set ${position + 1}`,
        description: asString(entry.description) === name ? '' : asString(entry.description),
        classification,
        confidentiality: level('precogly:confidentiality'),
        integrity: level('precogly:integrity'),
        availability: level('precogly:availability'),
        complianceTags: firstProfile ? stringList(firstProfile.regulations) : [],
        dataSensitivity: jsonPropertyItems(properties, 'precogly:data-sensitivity-tags').filter((item): item is string => typeof item === 'string'),
        ...(ref ? { bomRef: ref } : {}),
        passthrough,
      }
    })
  }

  readAssumptions(blueprint: CycloneDxBlueprint): GuestAssumption[] {
    return this.entries(blueprint, 'assumptions').map((entry, position) => {
      const ref = asString(entry['bom-ref'])
      const label = asString(entry.description) || ref || `assumption ${position}`
      const validityRaw = asString(entry.validity)
      let validity: GuestAssumption['validity'] = 'unverified'
      if (validityRaw === 'verified' || validityRaw === 'invalid' || validityRaw === 'unknown' || validityRaw === 'unverified') {
        validity = validityRaw
      } else if (validityRaw) {
        this.warn(`Assumption '${label}': validity '${validityRaw}' is not a CycloneDX value; shown as unverified.`)
      }
      const topicName = typeName(entry.topic)
      const topicKnown = ['availability', 'business', 'compliance', 'operational', 'performance', 'security', 'technical'].includes(topicName)
      const passthrough: JsonObject = {}
      for (const [key, value] of Object.entries(entry)) {
        if (!ENTRY_KNOWN_KEYS.assumptions.has(key)) passthrough[key] = deepClone(value)
      }
      if (topicName && !topicKnown) {
        passthrough.__customTopic = isObject(entry.topic) ? deepClone(entry.topic) : { name: topicName }
        this.warn(`Assumption '${label}': topic '${topicName}' is not a CycloneDX value; shown without a topic and kept for the file.`)
      }
      return {
        id: ref || `assumption-${uuid()}`,
        description: asString(entry.description),
        validity,
        topic: topicKnown ? topicName : '',
        ...(ref ? { bomRef: ref } : {}),
        passthrough,
      }
    })
  }

  readScope(blueprint: CycloneDxBlueprint): GuestOutOfScopeItem[] {
    const scope = isObject(blueprint.scope) ? blueprint.scope : null
    if (!scope) return []
    this.kept.hadScope = true
    const items: GuestOutOfScopeItem[] = []
    const unresolved: string[] = []
    for (const ref of stringList(scope.excludedComponents)) {
      const nodeId = this.index.nodes.get(ref)
      const node = nodeId ? this.nodes.find((candidate) => candidate.id === nodeId) : undefined
      if (node) items.push({ id: `oos-${uuid()}`, name: nodeLabel(node, ref), reason: '' })
      else unresolved.push(ref)
    }
    if (unresolved.length > 0) {
      this.warn(`Scope: ${unresolved.length} excluded component(s) are not on the diagram and are kept for the file.`)
    }
    const properties = readProperties(scope.properties, PROPERTY_OWNER.SCOPE)
    for (const item of jsonPropertyItems(properties, 'precogly:out-of-scope')) {
      if (isObject(item) && asString(item.name)) items.push({ id: `oos-${uuid()}`, name: asString(item.name), reason: asString(item.reason) })
    }
    for (const [key, value] of Object.entries(scope)) {
      if (!['name', 'excludedComponents'].includes(key)) this.kept.scope[key] = deepClone(value)
    }
    if (unresolved.length > 0) this.kept.scope.__extraExcluded = unresolved
    return items
  }

  // -- targets ------------------------------------------------------------

  private resolveTargets(refs: unknown, what: string): { targets: GuestTargetRef[]; hidden: string[]; hiddenInBlueprints: number; namesSystem: boolean } {
    const targets: GuestTargetRef[] = []
    const hidden: string[] = []
    let hiddenInBlueprints = 0
    let namesSystem = false
    for (const ref of Array.isArray(refs) ? refs : []) {
      if (typeof ref !== 'string') continue
      if (ref === this.systemRef && this.systemRef) {
        namesSystem = true
        continue
      }
      const nodeId = this.index.nodes.get(ref)
      if (nodeId) {
        const type = this.nodeTypeByRef.get(ref) === 'trustZone' ? 'zone' : 'component'
        if (!targets.some((target) => target.id === nodeId)) targets.push({ id: nodeId, type })
        continue
      }
      const edgeId = this.index.edges.get(ref)
      if (edgeId) {
        const edge = this.edges.find((candidate) => candidate.id === edgeId)
        const type = edge?.type === 'trustBoundary' ? 'boundary' : 'flow'
        if (!targets.some((target) => target.id === edgeId)) targets.push({ id: edgeId, type })
        continue
      }
      if (!hidden.includes(ref)) {
        hidden.push(ref)
        if (this.extraBlueprintRefs.has(ref)) hiddenInBlueprints += 1
      }
    }
    if (hidden.length > 0) {
      this.warn(`${what}: ${hidden.length} target(s) are not on this diagram and are kept for the file: ${hidden.join(', ')}.`)
    }
    return { targets, hidden, hiddenInBlueprints, namesSystem }
  }

  // -- threats --------------------------------------------------------------

  readThreats(): { threats: GuestThreat[]; scenarioRefToId: Map<string, string>; abstractToThreatIds: Map<string, string[]> } {
    const section = isObject(this.document.threats) ? this.document.threats : {}
    const abstractList = Array.isArray(section.threats) ? section.threats : []
    for (const item of abstractList) {
      if (!isObject(item) || typeof item['bom-ref'] !== 'string') continue
      this.kept.abstractThreats[item['bom-ref']] = deepClone(item)
      this.kept.abstractThreatOrder.push(item['bom-ref'])
    }
    const scenarios = Array.isArray(section.scenarios) ? section.scenarios : []
    const usedNumbers = new Set<number>()
    const threats: GuestThreat[] = []
    const scenarioRefToId = new Map<string, string>()
    const abstractToThreatIds = new Map<string, string[]>()
    scenarios.forEach((scenario, position) => {
      if (!isObject(scenario)) {
        this.warn(`Scenario ${position} is not an object and was skipped.`)
        return
      }
      const ref = asString(scenario['bom-ref'])
      const label = entryLabel(scenario, `scenario ${position}`)
      const abstractRefs = stringList(scenario.threats)
      const abstract = abstractRefs.length > 0 ? this.kept.abstractThreats[abstractRefs[0]] : undefined
      if (abstractRefs.length > 0 && !abstract) {
        this.warn(`Scenario '${label}': threat '${abstractRefs[0]}' is not declared in the file; shown as a custom threat.`)
      }
      if (abstractRefs.length === 0) this.warn(`Scenario '${label}' realizes no threat; shown as a custom threat.`)
      const properties = readProperties(scenario.properties, PROPERTY_OWNER.SCENARIO)
      const riskScore = isObject(scenario.riskScore) ? scenario.riskScore : null
      const levelRaw = asString(riskScore?.level)
      let level: GuestRatingLevel = 'medium'
      if ((RATING_LEVELS as readonly string[]).includes(levelRaw)) level = levelRaw as GuestRatingLevel
      else this.warn(`Scenario '${label}': ${levelRaw ? `level '${levelRaw}' is not a CycloneDX value` : 'it has no risk level'}; shown as medium.`)
      const strideEntry = (Array.isArray(abstract?.categories) ? abstract.categories : []).find(
        (category) => isObject(category) && category.taxonomy === 'STRIDE' && STRIDE_VALUES.has(asString(category.category))
      ) as JsonObject | undefined
      const triage = asString(properties.get('precogly:triage-status'))
      const status: ThreatStatus = (THREAT_STATUSES as readonly string[]).includes(triage) ? (triage as ThreatStatus) : 'open'
      const numberRaw = properties.get('precogly:number')
      let number = typeof numberRaw === 'number' && numberRaw >= 1 && !usedNumbers.has(numberRaw) ? numberRaw : null
      if (typeof numberRaw === 'number' && number === null) {
        this.warn(`Scenario '${label}': number ${numberRaw} is taken or invalid; a new one was given.`)
      }
      if (number === null) number = -1 // allocated after the loop, past the highest seen
      else usedNumbers.add(number)
      const { targets, hidden, hiddenInBlueprints, namesSystem } = this.resolveTargets(scenario.affectedAssets, `Threat '${label}'`)
      const wholeSystem = namesSystem || (!Array.isArray(scenario.affectedAssets) || scenario.affectedAssets.length === 0)
      const passthrough: JsonObject = {}
      for (const [key, value] of Object.entries(scenario)) {
        if (!ENTRY_KNOWN_KEYS.scenarios.has(key)) passthrough[key] = deepClone(value)
      }
      if (riskScore) passthrough.riskScore = deepClone(riskScore)
      if (Array.isArray(scenario.properties)) passthrough.properties = deepClone(scenario.properties)
      const id = ref || `threat-${uuid()}`
      const threat: GuestThreat = {
        id,
        number,
        name: asString(scenario.name) || asString(abstract?.name) || label,
        description: asString(scenario.description) || asString(abstract?.description),
        level,
        ...(strideEntry ? { category: asString(strideEntry.category) as STRIDECategory } : {}),
        status,
        ...(asString(properties.get('precogly:decision-rationale')) ? { decisionRationale: asString(properties.get('precogly:decision-rationale')) } : {}),
        targets,
        wholeSystem,
        hiddenTargetRefs: hidden,
        hiddenBlueprintTargetCount: hiddenInBlueprints,
        createdAt: new Date().toISOString(),
        ...(ref ? { bomRef: ref } : {}),
        ...(abstractRefs.length > 0 ? { abstractRefs } : {}),
        passthrough,
      }
      threats.push(threat)
      if (ref) scenarioRefToId.set(ref, id)
      for (const abstractRef of abstractRefs) {
        ;(abstractToThreatIds.get(abstractRef) ?? abstractToThreatIds.set(abstractRef, []).get(abstractRef)!).push(id)
      }
    })
    let next = Math.max(0, ...usedNumbers) + 1
    for (const threat of threats) {
      if (threat.number === -1) {
        threat.number = next
        next += 1
      }
    }
    return { threats, scenarioRefToId, abstractToThreatIds }
  }

  readControls(scenarioRefToId: Map<string, string>, abstractToThreatIds: Map<string, string[]>): GuestCountermeasure[] {
    const controlsRaw = this.document.controls
    if (controlsRaw !== undefined && !Array.isArray(controlsRaw)) {
      this.warn("The 'controls' section is not a list and was skipped.")
      return []
    }
    const usedNumbers = new Set<number>()
    const countermeasures: GuestCountermeasure[] = []
    const mitigatedBy = new Map<string, string[]>()
    for (const [abstractRef, entry] of Object.entries(this.kept.abstractThreats)) {
      for (const controlRef of stringList(entry.mitigations)) {
        ;(mitigatedBy.get(controlRef) ?? mitigatedBy.set(controlRef, []).get(controlRef)!).push(abstractRef)
      }
    }
    ;(controlsRaw ?? []).forEach((control: unknown, position: number) => {
      if (!isObject(control)) {
        this.warn(`Control ${position} is not an object and was skipped.`)
        return
      }
      const ref = asString(control['bom-ref'])
      const label = entryLabel(control, `control ${position}`)
      const properties = readProperties(control.properties, PROPERTY_OWNER.CONTROL)
      const functionsRaw = jsonPropertyItems(properties, 'precogly:control-functions')
      let controlFunction = functionsRaw.filter((item): item is ControlFunction => typeof item === 'string' && (CONTROL_FUNCTIONS as readonly string[]).includes(item))
      if (controlFunction.length === 0) {
        const category = typeName(control.category)
        controlFunction = (CONTROL_FUNCTIONS as readonly string[]).includes(category) ? [category as ControlFunction] : []
      }
      const natureRaw = asString(properties.get('precogly:control-nature'))
      const controlNature: ControlNature | '' = (CONTROL_NATURES as readonly string[]).includes(natureRaw) ? (natureRaw as ControlNature) : ''
      const numberRaw = properties.get('precogly:number')
      const number = typeof numberRaw === 'number' && numberRaw >= 1 && !usedNumbers.has(numberRaw) ? numberRaw : -1
      if (typeof numberRaw === 'number' && number === -1) this.warn(`Control '${label}': number ${numberRaw} is taken or invalid; a new one was given.`)
      if (number !== -1) usedNumbers.add(number)
      const mitigates = jsonPropertyItems(properties, 'precogly:mitigates').filter((item): item is string => typeof item === 'string')
      let threatIds: string[]
      if (mitigates.length > 0) {
        threatIds = mitigates.map((scenarioRef) => scenarioRefToId.get(scenarioRef)).filter((id): id is string => id !== undefined)
        if (threatIds.length < mitigates.length) this.warn(`Control '${label}': ${mitigates.length - threatIds.length} mitigated threat(s) were not found in the file.`)
      } else {
        threatIds = []
        for (const abstractRef of mitigatedBy.get(ref) ?? []) {
          for (const threatId of abstractToThreatIds.get(abstractRef) ?? []) {
            if (!threatIds.includes(threatId)) threatIds.push(threatId)
          }
        }
      }
      const { targets, hidden } = this.resolveTargets(control.appliesTo, `Control '${label}'`)
      const passthrough: JsonObject = {}
      for (const [key, value] of Object.entries(control)) {
        if (!ENTRY_KNOWN_KEYS.controls.has(key)) passthrough[key] = deepClone(value)
      }
      if (control.status !== undefined) passthrough.status = deepClone(control.status)
      if (Array.isArray(control.properties)) passthrough.properties = deepClone(control.properties)
      countermeasures.push({
        id: ref || `countermeasure-${uuid()}`,
        number,
        threatIds,
        name: asString(control.name) || label,
        description: asString(control.description),
        controlFunction,
        controlNature,
        targets,
        hiddenTargetRefs: hidden,
        createdAt: new Date().toISOString(),
        ...(ref ? { bomRef: ref } : {}),
        passthrough,
      })
    })
    let next = Math.max(0, ...usedNumbers) + 1
    for (const countermeasure of countermeasures) {
      if (countermeasure.number === -1) {
        countermeasure.number = next
        next += 1
      }
    }
    return countermeasures
  }

  readTrustBoundaries(): void {
    const section = isObject(this.document.threats) ? this.document.threats : {}
    for (const entry of Array.isArray(section.trustBoundaries) ? section.trustBoundaries : []) {
      if (!isObject(entry) || typeof entry.boundary !== 'string') continue
      this.kept.trustBoundaries[entry.boundary] = deepClone(entry)
      ;(this.kept.entryOrder.trustBoundaries ??= []).push(asString(entry['bom-ref']))
    }
  }

  // -- identity and counters ------------------------------------------------

  readIdentity(threats: GuestThreat[], countermeasures: GuestCountermeasure[]): GuestDocumentState {
    const serialRaw = asString(this.document.serialNumber)
    let serialNumber = serialRaw
    if (!SERIAL_PATTERN.test(serialRaw)) {
      serialNumber = newSerialNumber()
      this.warn(serialRaw ? `Serial number '${serialRaw}' is not a UUID URN; a new one was given.` : 'The file has no serial number; a new one was given.')
    }
    const versionRaw = this.document.version
    let version = 1
    if (typeof versionRaw === 'number' && Number.isInteger(versionRaw) && versionRaw >= 1) version = versionRaw
    else if (versionRaw !== undefined) this.warn(`Version '${String(versionRaw)}' is not a positive integer; shown as 1.`)
    const properties = readProperties(this.document.properties, PROPERTY_OWNER.DOCUMENT)
    const highestThreat = Math.max(0, ...threats.map((threat) => threat.number))
    const highestCountermeasure = Math.max(0, ...countermeasures.map((countermeasure) => countermeasure.number))
    const nextThreatRaw = properties.get('precogly:next-threat-number')
    const nextCountermeasureRaw = properties.get('precogly:next-countermeasure-number')
    return {
      serialNumber,
      version,
      exportDigest: null,
      nextThreatNumber: Math.max(highestThreat + 1, typeof nextThreatRaw === 'number' ? nextThreatRaw : 1),
      nextCountermeasureNumber: Math.max(highestCountermeasure + 1, typeof nextCountermeasureRaw === 'number' ? nextCountermeasureRaw : 1),
      kept: this.kept,
    }
  }

  readSession(): GuestSystemContext['session'] {
    const session = { facilitator: '', participants: [] as string[], meetingDate: '' }
    const property = this.kept.documentProperties.find((item) => item.name === GUEST_SESSION_PROPERTY)
    if (!property || typeof property.value !== 'string') return session
    try {
      const parsed: unknown = JSON.parse(property.value)
      if (isObject(parsed)) {
        session.facilitator = asString(parsed.facilitator)
        session.participants = stringList(parsed.participants)
        session.meetingDate = asString(parsed.meetingDate)
      }
    } catch {
      this.warn('The session details in the file could not be read.')
    }
    return session
  }

  readCriticality(): GuestSystemContext['systemInfo']['criticality'] {
    const properties = readProperties(this.kept.metadataComponent?.properties, PROPERTY_OWNER.SYSTEM)
    const raw = asString(properties.get('precogly:criticality'))
    return SPEC_TO_CRITICALITY[raw] ?? 'medium'
  }
}

export function deserializeCycloneDxToGuest(json: string): DeserializedFile {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('Could not parse file as JSON. Check that the file is valid JSON and try again.')
  }
  if (!isObject(parsed)) {
    throw new Error('Could not parse file as JSON. The file content must be a JSON object.')
  }
  if (!parsed.specFormat) {
    throw new Error("This file is not in CycloneDX format. The file must have a 'specFormat' field set to 'CycloneDX'.")
  }
  if (parsed.specFormat !== 'CycloneDX') {
    throw new Error(`This is not a CycloneDX file. Found specFormat '${String(parsed.specFormat)}' but expected 'CycloneDX'.`)
  }
  const specVersion = asString(parsed.specVersion)
  if (!specVersion.startsWith('2.')) {
    throw new Error(`Unsupported CycloneDX version '${specVersion || 'unknown'}'. Only version 2.x files are supported.`)
  }

  const importer = new Importer(parsed)
  importer.readDocumentLevel()
  const blueprint = importer.readBlueprint()
  const systemContext = emptySystemContext()
  if (blueprint) {
    importer.readCanvas(blueprint)
    importer.readZones(blueprint)
    importer.readAssets(blueprint, 'assets')
    importer.readAssets(blueprint, 'dataStores')
    importer.readFlows(blueprint)
    importer.readBoundaries(blueprint)
    systemContext.dataAssets = importer.readDataSets(blueprint)
    systemContext.assumptions = importer.readAssumptions(blueprint)
    systemContext.outOfScopeItems = importer.readScope(blueprint)
    systemContext.systemInfo.description = asString(blueprint.description)
  }
  importer.readTrustBoundaries()
  const { threats, scenarioRefToId, abstractToThreatIds } = importer.readThreats()
  const countermeasures = importer.readControls(scenarioRefToId, abstractToThreatIds)
  systemContext.session = importer.readSession()
  systemContext.systemInfo.criticality = importer.readCriticality()
  const documentState = importer.readIdentity(threats, countermeasures)
  const hiddenBlueprintCount = documentState.kept.extraBlueprints.length
  if (hiddenBlueprintCount > 0) {
    importer.warn(`This file has ${hiddenBlueprintCount} more blueprint${hiddenBlueprintCount === 1 ? '' : 's'}. ${hiddenBlueprintCount === 1 ? 'It is' : 'They are'} not shown here and ${hiddenBlueprintCount === 1 ? 'is' : 'are'} kept when you save.`)
  }
  if (importer.hiddenElementCount > 0) {
    importer.warn(`${importer.hiddenElementCount} element${importer.hiddenElementCount === 1 ? '' : 's'} of the blueprint ${importer.hiddenElementCount === 1 ? 'is' : 'are'} not on the diagram. ${importer.hiddenElementCount === 1 ? 'It is' : 'They are'} kept when you save.`)
  }
  const notationRaw = asString(documentState.kept.canvasExtras.notation_style)
  const notationStyle = notationRaw === 'dfd3' || notationRaw === 'yourdon' ? notationRaw : undefined
  const title = blueprint?.name || 'Untitled Diagram'

  const loaded: DeserializedFile = {
    title,
    nodes: importer.nodes,
    edges: importer.edges,
    threats,
    countermeasures,
    systemContext,
    ...(notationStyle ? { notationStyle } : {}),
    documentState,
    warnings: importer.warnings,
    hiddenBlueprintCount,
    hiddenElementCount: importer.hiddenElementCount,
  }
  // Saving an unchanged document keeps its version: the digest of what a save
  // would write right now is the baseline (I4).
  loaded.documentState.exportDigest = buildGuestDocument({
    title,
    nodes: loaded.nodes,
    edges: loaded.edges,
    threats,
    countermeasures,
    systemContext,
    notationStyle,
    documentState: loaded.documentState,
  }).digest
  return loaded
}
