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

/**
 * A cell is an object rather than a bare string so that a cell can later hold a
 * diagram node (draw.io-style container tables, where a Process sits inside a
 * cell and edges connect to it) by adding an optional field. Widening
 * `string` to an object afterwards would mean migrating every saved diagram.
 */
export interface TableCell {
  text: string
}

export interface TableRow {
  height: number
  cells: TableCell[]
}

/**
 * The table sizes itself: outer width is the sum of `columnWidths`, outer height
 * the sum of row heights. React Flow v12 measures node DOM, so no `style.width`
 * is set and there is only one source of truth for the dimensions. Consequently
 * the table is resized by dragging column and row dividers, not by NodeResizer.
 */
export interface TableNodeData extends BaseNodeData {
  rows: TableRow[]
  columnWidths: number[]
  headerRow: boolean
  /**
   * Cell text size in px. Only a shift-corner-drag changes it, matching Miro,
   * where a plain corner drag resizes cells and leaves text alone while shift
   * scales the table uniformly and the text with it.
   *
   * Optional so tables saved before this existed keep working; absent means
   * TABLE_DEFAULT_FONT_SIZE.
   */
  fontSize?: number
}

/**
 * Whether a node can carry component threats, and so whether the edit panel
 * offers a threat section.
 *
 * Trust zones are excluded because their threats attach to the boundary rather
 * than the zone; sticky notes and tables are excluded because they are
 * annotations with no DFD semantics at all.
 */
export function nodeSupportsComponentThreats(type: string | undefined): boolean {
  return type !== 'trustZone' && type !== 'stickyNote' && type !== 'table'
}

/** Matches Tailwind's text-xs, which is what the cells rendered at before this was configurable. */
export const TABLE_DEFAULT_FONT_SIZE = 12
export const TABLE_MIN_FONT_SIZE = 6

export const TABLE_DEFAULT_COLUMN_WIDTH = 120
export const TABLE_DEFAULT_ROW_HEIGHT = 36
export const TABLE_MIN_COLUMN_WIDTH = 48
export const TABLE_MIN_ROW_HEIGHT = 24
export const TABLE_DEFAULT_COLUMNS = 3
export const TABLE_DEFAULT_ROWS = 3

/**
 * Set the column count, growing with empty cells or truncating from the right.
 * Truncating discards whatever was in the dropped cells; that is recoverable
 * through the editor's undo stack, which is why there is no confirmation.
 */
export function setTableColumnCount(
  current: TableNodeData,
  count: number
): Pick<TableNodeData, 'columnWidths' | 'rows'> {
  const target = Math.max(1, Math.floor(count))
  const existing = current.columnWidths.length

  if (target === existing) return { columnWidths: current.columnWidths, rows: current.rows }

  const columnWidths =
    target < existing
      ? current.columnWidths.slice(0, target)
      : [
          ...current.columnWidths,
          ...Array.from({ length: target - existing }, () => TABLE_DEFAULT_COLUMN_WIDTH),
        ]

  const rows = current.rows.map((row) => ({
    ...row,
    cells:
      target < existing
        ? row.cells.slice(0, target)
        : [...row.cells, ...Array.from({ length: target - existing }, () => ({ text: '' }))],
  }))

  return { columnWidths, rows }
}

/** Insert an empty column at `index`, shifting the rest right. */
export function insertTableColumn(
  current: TableNodeData,
  index: number
): Pick<TableNodeData, 'columnWidths' | 'rows'> {
  const at = Math.min(current.columnWidths.length, Math.max(0, index))
  return {
    columnWidths: [
      ...current.columnWidths.slice(0, at),
      TABLE_DEFAULT_COLUMN_WIDTH,
      ...current.columnWidths.slice(at),
    ],
    rows: current.rows.map((row) => ({
      ...row,
      cells: [...row.cells.slice(0, at), { text: '' }, ...row.cells.slice(at)],
    })),
  }
}

/** Insert an empty row at `index`, shifting the rest down. */
export function insertTableRow(current: TableNodeData, index: number): Pick<TableNodeData, 'rows'> {
  const at = Math.min(current.rows.length, Math.max(0, index))
  return {
    rows: [
      ...current.rows.slice(0, at),
      {
        height: TABLE_DEFAULT_ROW_HEIGHT,
        cells: current.columnWidths.map(() => ({ text: '' })),
      },
      ...current.rows.slice(at),
    ],
  }
}

/** Remove one column. A no-op on the last one, which cannot be removed. */
export function removeTableColumn(
  current: TableNodeData,
  index: number
): Pick<TableNodeData, 'columnWidths' | 'rows'> {
  if (current.columnWidths.length <= 1) {
    return { columnWidths: current.columnWidths, rows: current.rows }
  }
  return {
    columnWidths: current.columnWidths.filter((_, ci) => ci !== index),
    rows: current.rows.map((row) => ({ ...row, cells: row.cells.filter((_, ci) => ci !== index) })),
  }
}

/** Remove one row. A no-op on the last one, which cannot be removed. */
export function removeTableRow(current: TableNodeData, index: number): Pick<TableNodeData, 'rows'> {
  if (current.rows.length <= 1) return { rows: current.rows }
  return { rows: current.rows.filter((_, ri) => ri !== index) }
}

/** Set the row count, growing with empty rows or truncating from the bottom. */
export function setTableRowCount(current: TableNodeData, count: number): Pick<TableNodeData, 'rows'> {
  const target = Math.max(1, Math.floor(count))
  const existing = current.rows.length

  if (target === existing) return { rows: current.rows }

  return {
    rows:
      target < existing
        ? current.rows.slice(0, target)
        : [
            ...current.rows,
            ...Array.from({ length: target - existing }, () => ({
              height: TABLE_DEFAULT_ROW_HEIGHT,
              cells: current.columnWidths.map(() => ({ text: '' })),
            })),
          ],
  }
}

/**
 * There is deliberately no upper bound on a table's size: a requested count is
 * honoured rather than clamped, so typing 200 rows makes 200 rows.
 *
 * The cost is real and unpaid for. Every cell is a rendered DOM node with no
 * virtualization, so a 20 x 200 table is 4000 elements the canvas walks on
 * every pan and zoom. If large tables turn out to be common, the fix is to
 * virtualize the cell grid, not to reintroduce a limit.
 *
 * The lower bound of one column and one row is structural rather than a policy:
 * a table with none has no cell to click and no way back.
 */
/** An empty table of the given size, defaulting to a header row plus two body rows. */
export function createDefaultTableData(
  columns: number = TABLE_DEFAULT_COLUMNS,
  rows: number = TABLE_DEFAULT_ROWS
): Pick<TableNodeData, 'rows' | 'columnWidths' | 'headerRow'> {
  const columnCount = Math.max(1, Math.floor(columns))
  const rowCount = Math.max(1, Math.floor(rows))

  return {
    columnWidths: Array.from({ length: columnCount }, () => TABLE_DEFAULT_COLUMN_WIDTH),
    rows: Array.from({ length: rowCount }, () => ({
      height: TABLE_DEFAULT_ROW_HEIGHT,
      cells: Array.from({ length: columnCount }, () => ({ text: '' })),
    })),
    headerRow: true,
  }
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
  | TableNodeData

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
