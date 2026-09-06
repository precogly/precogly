import type { Node, Edge } from '@xyflow/react'
import type { DFDNotationStyle } from './notation'

// Re-export domain types for convenience
export {
  type DiagramNodeType,
  type TrustZonePresetName,
  type DataClassification,
  type Protocol,
  type DataSensitivity,
  type TemplateCategory,
  type DiagramTypeValue,
  type ThreatFramework,
  ZONE_COLOR_OPTIONS,
  getZoneColorConfig,
  TRUST_ZONE_PRESET_NAMES,
  DATA_CLASSIFICATIONS,
  PROTOCOLS,
  DATA_SENSITIVITY_CONFIG,
  formatCategoryLabel,
} from '@/types/domain'

import type {
  DiagramNodeType,
  DataClassification,
  Protocol,
  DataSensitivity,
  DiagramTypeValue,
  ThreatFramework,
} from '@/types/domain'

// Node Data Types
export interface BaseNodeData {
  label: string
  description?: string
  isNewlyInserted?: boolean
  isInlineEditing?: boolean
  lockAnimationKey?: number     // Timestamp to trigger lock animation (child locked into parent)
  receiveChildAnimationKey?: number  // Timestamp to trigger animation (container received a child)
  [key: string]: unknown  // Required for React Flow's Node<T> constraint
}

export interface ProcessNodeData extends BaseNodeData {
  technology?: string
  dataSensitivity?: DataSensitivity
  // Backend component ID of the parent process (for sync to OrgsystemComponent.parent_component)
  parentComponentId?: number
}

export interface DataStoreNodeData extends BaseNodeData {
  technology?: string
  dataSensitivity?: DataSensitivity
  dataStoreType?: string
}

export interface HumanActorNodeData extends BaseNodeData {
  actorType?: string
  technology?: string
}

export interface SystemActorNodeData extends BaseNodeData {
  systemType?: string
  vendor?: string
  technology?: string
}

export interface TrustZoneNodeData extends BaseNodeData {
  // Trust level 0-100 (0 = untrusted/internet, 100 = restricted)
  trustLevel?: number
  // User-chosen zone color (borderColor hex, e.g., '#22c55e')
  zoneColor?: string
  // Technology implementing this zone (e.g., AWS VPC, Azure VNet)
  technology?: string
  // Written back by backend sync (trust_zone_id → trustZoneId)
  trustZoneId?: number
}

export interface SystemScopeNodeData extends BaseNodeData {
  owner?: string
  classification?: string
  technology?: string
  orgsystemId?: number
}

export type StickyNoteColor = 'yellow' | 'blue' | 'green' | 'pink' | 'orange'
export type StickyNoteTextSize = 'small' | 'medium' | 'large'

export interface StickyNoteNodeData extends BaseNodeData {
  noteColor?: StickyNoteColor
  textSize?: StickyNoteTextSize
  bold?: boolean
  italic?: boolean
}

// Union type for all node data
export type DiagramNodeData =
  | ProcessNodeData
  | DataStoreNodeData
  | HumanActorNodeData
  | SystemActorNodeData
  | TrustZoneNodeData
  | SystemScopeNodeData
  | StickyNoteNodeData

// Edge Data
export interface DataFlowEdgeData {
  label?: string
  description?: string
  protocol?: Protocol
  dataClassification?: DataClassification[]
  encrypted?: boolean
  authenticated?: boolean
  hasSensitiveData?: boolean
  isNewlyInserted?: boolean
  // Backend data flow ID (written back by diagram sync)
  dataflowId?: number
  // Trust zone crossing
  crossesZoneId?: string           // ID of the zone this flow crosses
  crossesZoneLabel?: string        // Label of the zone (for display)
  crossesZoneTrustLevel?: number   // Trust level of the zone
  crossesZoneColor?: string        // Color of the zone (borderColor hex)
  crossesZoneIds?: string[]        // For flows crossing multiple zones
  [key: string]: unknown  // Required for React Flow's Edge<T> constraint
}

// Trust Boundary edge types
export type AccessControlMethod = 'none' | 'acl' | 'rbac' | 'mac' | 'dac' | 'abac'
export const ACCESS_CONTROL_METHODS: { value: AccessControlMethod; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'acl', label: 'ACL' },
  { value: 'rbac', label: 'RBAC' },
  { value: 'mac', label: 'MAC' },
  { value: 'dac', label: 'DAC' },
  { value: 'abac', label: 'ABAC' },
]

export type AuthenticationMethod =
  | 'none' | 'password' | 'otp' | 'challengeResponse'
  | 'publicKey' | 'token' | 'biometrics' | 'sso' | 'social'
export const AUTHENTICATION_METHODS: { value: AuthenticationMethod; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'password', label: 'Password' },
  { value: 'otp', label: 'OTP' },
  { value: 'challengeResponse', label: 'Challenge/Response' },
  { value: 'publicKey', label: 'Public Key' },
  { value: 'token', label: 'Token' },
  { value: 'biometrics', label: 'Biometrics' },
  { value: 'sso', label: 'SSO' },
  { value: 'social', label: 'Social' },
]

export interface TrustBoundaryEdgeData {
  label?: string
  accessControlMethods?: AccessControlMethod[]
  authenticationMethods?: AuthenticationMethod[]
  accessTokenExpires?: boolean
  accessTokenTtl?: number
  hasRefreshToken?: boolean
  refreshTokenExpires?: boolean
  refreshTokenTtl?: number
  canUserLogout?: boolean
  canSystemLogout?: boolean
  // Written back by backend sync (trust_boundary_id → trustBoundaryId)
  trustBoundaryId?: number
  [key: string]: unknown
}

// Type aliases for React Flow nodes/edges with our data
export type DiagramNode = Node<DiagramNodeData, DiagramNodeType>
export type DataFlowEdge = Edge<DataFlowEdgeData>
export type TrustBoundaryEdge = Edge<TrustBoundaryEdgeData>
export type DiagramEdge = DataFlowEdge | TrustBoundaryEdge

// Canvas data structure
export interface CanvasData {
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  notationStyle?: DFDNotationStyle
}

// Diagram entity
export interface Diagram {
  id: string
  name: string
  diagramType?: DiagramTypeValue
  isPrimary?: boolean
  threatModel?: number
  canvasData?: CanvasData
  updatedBy?: string
  updatedByEmail?: string
  createdAt?: string
  updatedAt?: string
}

export interface CreateDiagramInput {
  threatModelId: string
  title: string
  description?: string
  diagramType?: DiagramTypeValue
  threatFramework?: ThreatFramework
}

// Clipboard data for copy/paste
export interface ClipboardData {
  nodes: DiagramNode[]
  edges: DiagramEdge[]
}

// Type guards
export function isProcessNode(node: DiagramNode): node is Node<ProcessNodeData, 'process'> {
  return node.type === 'process'
}

export function isDataStoreNode(node: DiagramNode): node is Node<DataStoreNodeData, 'datastore'> {
  return node.type === 'datastore'
}

export function isHumanActorNode(node: DiagramNode): node is Node<HumanActorNodeData, 'humanActor'> {
  return node.type === 'humanActor'
}

export function isSystemActorNode(node: DiagramNode): node is Node<SystemActorNodeData, 'systemActor'> {
  return node.type === 'systemActor'
}

export function isTrustZoneNode(node: DiagramNode): node is Node<TrustZoneNodeData, 'trustZone'> {
  return node.type === 'trustZone'
}

export function isSystemScopeNode(node: DiagramNode): node is Node<SystemScopeNodeData, 'systemScope'> {
  return node.type === 'systemScope'
}

/** Returns true for nodes that are always containers (trust zones, system scopes). */
export function isContainerNode(node: DiagramNode): boolean {
  return node.type === 'trustZone' || node.type === 'systemScope'
}

/** Returns true for any node that can currently accept children.
 *  Trust zones and system scopes are always valid parents.
 *  Process nodes are valid parents when they already have children
 *  (i.e., another node's parentId points to them). */
export function isValidParentNode(node: DiagramNode, allNodes: DiagramNode[]): boolean {
  if (isContainerNode(node)) return true
  if (node.type === 'process') {
    return allNodes.some(n => n.parentId === node.id)
  }
  return false
}

/** Max depth for process-to-process nesting (Parent → Child → Grandchild). */
export const MAX_PROCESS_HIERARCHY_DEPTH = 3

/** Count process-to-process ancestor levels above a node. */
export function getProcessAncestorDepth(nodeId: string, allNodes: DiagramNode[]): number {
  const nodeMap = new Map(allNodes.map(n => [n.id, n]))
  let depth = 0
  let currentId = nodeMap.get(nodeId)?.parentId
  const visited = new Set<string>()
  while (currentId && !visited.has(currentId)) {
    visited.add(currentId)
    const parent = nodeMap.get(currentId)
    if (!parent) break
    if (parent.type === 'process') depth++
    currentId = parent.parentId
  }
  return depth
}

/** Count the deepest process-to-process descendant chain below a node. */
export function getProcessDescendantDepth(nodeId: string, allNodes: DiagramNode[]): number {
  const children = allNodes.filter(n => n.parentId === nodeId && n.type === 'process')
  if (children.length === 0) return 0
  return 1 + Math.max(...children.map(c => getProcessDescendantDepth(c.id, allNodes)))
}

// Edge type guards
export function isDataFlowEdge(edge: DiagramEdge): edge is DataFlowEdge {
  return edge.type === 'dataFlow'
}

export function isTrustBoundaryEdge(edge: DiagramEdge): edge is TrustBoundaryEdge {
  return edge.type === 'trustBoundary'
}
