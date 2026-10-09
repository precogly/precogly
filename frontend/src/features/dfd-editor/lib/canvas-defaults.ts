/**
 * Read-side accessors for the canvas keys added by issues #583/#584 (plan
 * section 11.2).
 *
 * A canvas that does not set a type (most pack templates, AI output, every
 * diagram saved before this change) needs no rewrite: every reader goes
 * through these and gets the default when the key is missing or holds a value
 * outside the spec list. The defaults match the backend's DFD sync
 * (`apps.diagrams.services`), so what the editor shows is what the row says.
 */

import {
  AUTHENTICATION_TYPES,
  BOUNDARY_TYPES,
  COMPONENT_KINDS,
  DEFAULT_BOUNDARY_TYPE,
  DEFAULT_COMPONENT_KIND,
  DEFAULT_FLOW_TYPE,
  DEFAULT_ZONE_TYPE,
  FLOW_TYPES,
  UNSPECIFIED_AUTHENTICATION,
  ZONE_TYPES,
  type AuthenticationType,
  type BoundaryType,
  type ComponentKind,
  type FlowType,
  type ZoneType,
} from '@/types/domain'

export { isAuthenticated, requiresAuthorization } from '@/lib/authentication'

type CanvasData = Record<string, unknown> | null | undefined

const ZONE_TYPE_VALUES = new Set<string>(ZONE_TYPES.map((entry) => entry.value))
const BOUNDARY_TYPE_VALUES = new Set<string>(BOUNDARY_TYPES.map((entry) => entry.value))
const FLOW_TYPE_VALUES = new Set<string>(FLOW_TYPES.map((entry) => entry.value))
const COMPONENT_KIND_VALUES = new Set<string>(COMPONENT_KINDS.map((entry) => entry.value))
const AUTHENTICATION_VALUES = new Set<string>(AUTHENTICATION_TYPES.map((entry) => entry.value))

/** The zone type of a trust zone node; `trust` when unset or unknown. */
export function getZoneType(data: CanvasData): ZoneType {
  const value = data?.zoneType
  return typeof value === 'string' && ZONE_TYPE_VALUES.has(value) ? (value as ZoneType) : DEFAULT_ZONE_TYPE
}

/** The flow type of a data flow edge; `data` when unset or unknown. */
export function getFlowType(data: CanvasData): FlowType {
  const value = data?.flowType
  return typeof value === 'string' && FLOW_TYPE_VALUES.has(value) ? (value as FlowType) : DEFAULT_FLOW_TYPE
}

/** The boundary type of a trust boundary edge; `trust` when unset or unknown. */
export function getBoundaryType(data: CanvasData): BoundaryType {
  const value = data?.boundaryType
  return typeof value === 'string' && BOUNDARY_TYPE_VALUES.has(value)
    ? (value as BoundaryType)
    : DEFAULT_BOUNDARY_TYPE
}

/**
 * The default kind for a canvas node type, mirroring the backend's
 * CATEGORY_TO_KIND by the category the node syncs to (a system scope syncs
 * to a `system` component, plan F20).
 */
export function kindForNodeType(nodeType: string | undefined): ComponentKind {
  switch (nodeType) {
    case 'process':
      return 'process'
    case 'datastore':
      return 'data-store'
    case 'humanActor':
    case 'systemActor':
      return 'actor'
    case 'systemScope':
      return 'system'
    default:
      return DEFAULT_COMPONENT_KIND
  }
}

/** A component node's kind: the `kind` key when set and known, else the default for its node type. */
export function getComponentKind(data: CanvasData, nodeType: string | undefined): ComponentKind {
  const value = data?.kind
  if (typeof value === 'string' && COMPONENT_KIND_VALUES.has(value)) return value as ComponentKind
  return kindForNodeType(nodeType)
}

/**
 * A flow edge's authentication list. Missing means an empty list (not
 * recorded). A canvas saved with the retired boolean `authenticated: true` is
 * read as `[unspecified]`, which is what the backend sync stores for it (I9).
 * Values outside the spec list are kept: an import may carry a custom name.
 */
export function getAuthentication(data: CanvasData): AuthenticationType[] {
  const value = data?.authentication
  if (Array.isArray(value)) {
    return value.filter((entry): entry is AuthenticationType => typeof entry === 'string' && entry !== '')
  }
  if (data?.authenticated === true) return [UNSPECIFIED_AUTHENTICATION]
  return []
}

/** Whether a value is one of the spec's authentication types (or our `unspecified`). */
export function isKnownAuthenticationType(value: string): value is AuthenticationType {
  return AUTHENTICATION_VALUES.has(value)
}
