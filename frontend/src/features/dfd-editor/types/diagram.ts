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

import { AUTHENTICATION_TYPES } from '@/types/domain'
import type {
  DiagramNodeType,
  DataClassification,
  Protocol,
  DataSensitivity,
  DiagramTypeValue,
  ThreatFramework,
  ZoneType,
  BoundaryType,
  FlowType,
  ComponentKind,
  AuthenticationType,
  AuthorizationType,
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

/**
 * Keys shared by every node that syncs to a component row. `kind` is the
 * spec asset type; when missing it defaults from the node type (read it
 * through `getComponentKind` in lib/canvas-defaults.ts, never directly).
 */
export interface ComponentNodeDataFields {
  kind?: ComponentKind
  // Written back by backend sync (component_id)
  componentId?: number
}

export interface ProcessNodeData extends BaseNodeData, ComponentNodeDataFields {
  technology?: string
  dataSensitivity?: DataSensitivity
  // Backend component ID of the parent process (for sync to OrgsystemComponent.parent_component)
  parentComponentId?: number
}

export interface DataStoreNodeData extends BaseNodeData, ComponentNodeDataFields {
  technology?: string
  dataSensitivity?: DataSensitivity
  dataStoreType?: string
}

export interface HumanActorNodeData extends BaseNodeData, ComponentNodeDataFields {
  actorType?: string
  technology?: string
}

export interface SystemActorNodeData extends BaseNodeData, ComponentNodeDataFields {
  systemType?: string
  vendor?: string
  technology?: string
}

export interface TrustZoneNodeData extends BaseNodeData {
  // Spec zone type; missing means `trust` (read through `getZoneType`)
  zoneType?: ZoneType
  // Trust level 0-100 (0 = untrusted/internet, 100 = restricted). Missing
  // means "not set": the backend stores null and the indicator is hidden.
  trustLevel?: number
  // User-chosen zone color (borderColor hex, e.g., '#22c55e')
  zoneColor?: string
  // Technology implementing this zone (e.g., AWS VPC, Azure VNet)
  technology?: string
  // Written back by backend sync (trust_zone_id → trustZoneId)
  trustZoneId?: number
}

export interface SystemScopeNodeData extends BaseNodeData, ComponentNodeDataFields {
  owner?: string
  classification?: string
  technology?: string
  // The inventory system this scope stands for (optional, plan F20)
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
 * A cell is an object rather than a bare string so it can later hold a diagram
 * node (draw.io-style container tables, where a Process sits inside a cell and
 * edges connect to it) by gaining an optional field. Widening `string` to an
 * object afterwards would mean migrating every saved diagram.
 */
export interface TableCell {
  text: string
  fill?: TableCellFill
  /**
   * How far a merge anchored here reaches. Absent means one, so an unmerged
   * cell carries neither field and a diagram saved before merging existed is
   * already correct.
   *
   * The cells a merge swallows stay in `cells`, keeping the grid rectangular so
   * every index into it still means what it did. They are not flagged: which
   * cells are covered is derived from the anchors by `tableCoveredCells`,
   * because a stored flag and the span it mirrors are two things that can
   * disagree.
   */
  colSpan?: number
  rowSpan?: number
}

/**
 * A cell's background, stored as a palette name rather than a hex value. A dark
 * theme has to change what `blue` renders as, and a saved diagram full of
 * `#dbeafe` could not be remapped afterwards.
 *
 * Absent means no fill, which is not the same as white: an unfilled cell in the
 * header row still takes its slate tint from `headerRow`.
 */
export type TableCellFill =
  | 'gray'
  | 'red'
  | 'orange'
  | 'yellow'
  | 'green'
  | 'blue'
  | 'purple'
  | 'pink'

/**
 * The eight hues every comparable tool offers, in the order they are shown.
 *
 * Taken from the intersection of three palettes, checked 2026-09-16: Notion
 * (gray, brown, orange, yellow, green, blue, purple, pink, red), Google Sheets
 * (gray, red berry, red, orange, yellow, green, cyan, cornflower blue, blue,
 * purple, magenta) and Airtable (blue, cyan, gray, green, orange, pink, purple,
 * red, teal, yellow). Brown appears only in Notion; cyan and teal only in
 * Sheets and Airtable. These eight are in all three, so they are what a person
 * arriving from any of them expects to find.
 *
 * The values are Tailwind **v3** 100-level tints, not v4's. The project runs
 * Tailwind v4, whose palette moved to OKLCH and shifted every value, but these
 * are written out rather than resolved from the theme, so they stayed where
 * they were. That is deliberate: five of them are also the sticky note tints in
 * `NOTE_COLORS` (StickyNoteNode.tsx), and a yellow cell has to be the same
 * yellow as a yellow sticky note sitting beside it on the canvas. Moving one
 * set to v4 without the other would break that. Change both together.
 *
 * Gray is the exception, at the 200 level. The header row already paints itself
 * slate-100, so a slate-100 gray fill would do nothing visible on row 0 and
 * would read as a second header row anywhere else. A step darker keeps a
 * deliberate gray legible as one.
 *
 * The header takes its tint from a Tailwind class, so it renders whatever the
 * installed version resolves slate-100 to, while this is a frozen v3 hex. They
 * are a visible step apart under both, and table-node.spec.ts asserts that they
 * differ rather than pinning the header's value.
 *
 * All eight are light enough to leave the cells' slate-800 text readable
 * without a per-fill text color.
 */
export const TABLE_FILL_COLORS: Record<TableCellFill, string> = {
  gray: '#e2e8f0',
  red: '#fee2e2',
  orange: '#ffedd5',
  yellow: '#fef9c3',
  green: '#dcfce7',
  blue: '#dbeafe',
  purple: '#f3e8ff',
  pink: '#fce7f3',
}

export const TABLE_FILL_NAMES = Object.keys(TABLE_FILL_COLORS) as TableCellFill[]

export interface TableRow {
  height: number
  cells: TableCell[]
}

/**
 * The table sizes itself: outer width is the sum of `columnWidths`, and outer
 * height is at least the sum of row heights — more wherever a row has grown to
 * fit wrapped text. React Flow v12 measures node DOM, so no `style.width` is set
 * and the dimensions have one source of truth. The table is resized by dragging
 * a column or row divider or a corner handle, not by NodeResizer.
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
 * Drop the spans of every merge a structural edit cuts through.
 *
 * Inserting or deleting across a merge unmerges it rather than growing or
 * shrinking it. Neither spreadsheet does anything better: Excel expands the
 * selection to the merge's full extent, so inserting one row inside a ten-row
 * merge inserts ten, and Sheets often refuses the insert outright. Both leave
 * people doing unmerge / edit / re-merge by hand, which is what this does for
 * them. Undo puts the merge back.
 *
 * Checked 2026-09-16 against Microsoft's "Merge and unmerge cells in Excel" and
 * the reports under learn.microsoft.com/answers/questions/5033930.
 */
function unmergeCutBy(
  rows: TableRow[],
  isCut: (anchor: { row: number; col: number; rowSpan: number; colSpan: number }) => boolean
): TableRow[] {
  return rows.map((row, rowIndex) => ({
    ...row,
    cells: row.cells.map((cell, colIndex) => {
      const rowSpan = cell.rowSpan ?? 1
      const colSpan = cell.colSpan ?? 1
      if (rowSpan === 1 && colSpan === 1) return cell
      if (!isCut({ row: rowIndex, col: colIndex, rowSpan, colSpan })) return cell
      return withoutSpan(cell)
    }),
  }))
}

/**
 * Set the column count, growing with empty cells or truncating from the right.
 * Truncating discards whatever was in the dropped cells, recoverable through the
 * editor's undo stack, so there is no confirmation.
 */
export function setTableColumnCount(
  current: TableNodeData,
  count: number
): Pick<TableNodeData, 'columnWidths' | 'rows'> {
  const target = Math.max(1, Math.floor(count))
  const existing = current.columnWidths.length

  if (target === existing) return { columnWidths: current.columnWidths, rows: current.rows }

  // Truncating cuts any merge that reached past the new edge.
  const kept =
    target < existing
      ? unmergeCutBy(current.rows, ({ col, colSpan }) => col + colSpan > target)
      : current.rows

  const columnWidths =
    target < existing
      ? current.columnWidths.slice(0, target)
      : [
          ...current.columnWidths,
          ...Array.from({ length: target - existing }, () => TABLE_DEFAULT_COLUMN_WIDTH),
        ]

  const rows = kept.map((row) => ({
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
  const kept = unmergeCutBy(current.rows, ({ col, colSpan }) => col < at && at < col + colSpan)
  return {
    columnWidths: [
      ...current.columnWidths.slice(0, at),
      TABLE_DEFAULT_COLUMN_WIDTH,
      ...current.columnWidths.slice(at),
    ],
    rows: kept.map((row) => ({
      ...row,
      cells: [...row.cells.slice(0, at), { text: '' }, ...row.cells.slice(at)],
    })),
  }
}

/** Insert an empty row at `index`, shifting the rest down. */
export function insertTableRow(current: TableNodeData, index: number): Pick<TableNodeData, 'rows'> {
  const at = Math.min(current.rows.length, Math.max(0, index))
  const kept = unmergeCutBy(current.rows, ({ row, rowSpan }) => row < at && at < row + rowSpan)
  return {
    rows: [
      ...kept.slice(0, at),
      {
        height: TABLE_DEFAULT_ROW_HEIGHT,
        cells: current.columnWidths.map(() => ({ text: '' })),
      },
      ...kept.slice(at),
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
  const kept = unmergeCutBy(
    current.rows,
    ({ col, colSpan }) => col <= index && index < col + colSpan
  )
  return {
    columnWidths: current.columnWidths.filter((_, ci) => ci !== index),
    rows: kept.map((row) => ({ ...row, cells: row.cells.filter((_, ci) => ci !== index) })),
  }
}

/** Remove one row. A no-op on the last one, which cannot be removed. */
export function removeTableRow(current: TableNodeData, index: number): Pick<TableNodeData, 'rows'> {
  if (current.rows.length <= 1) return { rows: current.rows }
  const kept = unmergeCutBy(current.rows, ({ row, rowSpan }) => row <= index && index < row + rowSpan)
  return { rows: kept.filter((_, ri) => ri !== index) }
}

/**
 * A rectangle of cells, inclusive on all four sides. Always normalized, so
 * `top <= bottom` and `left <= right` whichever corner a drag started from.
 */
export interface TableCellRange {
  top: number
  left: number
  bottom: number
  right: number
}

export function tableRangeContains(range: TableCellRange, row: number, col: number): boolean {
  return row >= range.top && row <= range.bottom && col >= range.left && col <= range.right
}

/**
 * The cells hidden under a merge, keyed `"row,col"`, each mapped to the anchor
 * that covers it.
 *
 * Derived rather than stored; see `TableCell`. Rendering only asks whether a
 * cell is in here; the anchor is what lets an arrow key landing on a covered
 * cell select the block it belongs to instead of nothing.
 *
 * Bounded by the real grid so a span left over from an edit that outgrew it
 * cannot claim cells that no longer exist — the structural helpers clear such
 * spans, and this is the backstop if one ever slips through.
 */
export function tableCoveredCells(rows: TableRow[]): Map<string, { row: number; col: number }> {
  const covered = new Map<string, { row: number; col: number }>()
  const columnCount = rows[0]?.cells.length ?? 0

  rows.forEach((row, rowIndex) => {
    row.cells.forEach((cell, colIndex) => {
      const rowSpan = cell.rowSpan ?? 1
      const colSpan = cell.colSpan ?? 1
      if (rowSpan === 1 && colSpan === 1) return

      const lastRow = Math.min(rowIndex + rowSpan, rows.length)
      const lastCol = Math.min(colIndex + colSpan, columnCount)
      for (let r = rowIndex; r < lastRow; r++) {
        for (let c = colIndex; c < lastCol; c++) {
          if (r === rowIndex && c === colIndex) continue
          covered.set(`${r},${c}`, { row: rowIndex, col: colIndex })
        }
      }
    })
  })

  return covered
}

/** A copy of `cell` carrying no merge span. */
function withoutSpan(cell: TableCell): TableCell {
  const plain = { ...cell }
  delete plain.rowSpan
  delete plain.colSpan
  return plain
}

/**
 * Grow `range` until it contains every merge it touches.
 *
 * Merging a range that cuts an existing merge in half would leave an anchor
 * outside the new block still claiming cells inside it — two anchors covering
 * one cell, which nothing downstream can render sensibly. Swallowing the whole
 * merge instead is what Sheets does. Iterated to a fixed point because widening
 * to absorb one merge can bring the edge up against another.
 */
export function expandRangeOverMerges(rows: TableRow[], range: TableCellRange): TableCellRange {
  let { top, left, bottom, right } = range

  for (let pass = 0; pass < rows.length + 1; pass++) {
    let grew = false

    rows.forEach((row, rowIndex) => {
      row.cells.forEach((cell, colIndex) => {
        const cellBottom = rowIndex + (cell.rowSpan ?? 1) - 1
        const cellRight = colIndex + (cell.colSpan ?? 1) - 1
        const intersects =
          rowIndex <= bottom && cellBottom >= top && colIndex <= right && cellRight >= left
        if (!intersects) return

        if (rowIndex < top) {
          top = rowIndex
          grew = true
        }
        if (colIndex < left) {
          left = colIndex
          grew = true
        }
        if (cellBottom > bottom) {
          bottom = cellBottom
          grew = true
        }
        if (cellRight > right) {
          right = cellRight
          grew = true
        }
      })
    })

    if (!grew) break
  }

  return { top, left, bottom, right }
}

/**
 * Merge `range` into one cell.
 *
 * The anchor keeps its text and every other cell in the block is emptied, which
 * is Excel's and Sheets' rule. Neither warns here, unlike both of them: the
 * editor has undo, so the text is one keystroke away, and the table already
 * discards cells without asking when a row or column is removed.
 */
export function mergeTableCells(
  current: TableNodeData,
  range: TableCellRange
): Pick<TableNodeData, 'rows'> {
  const block = expandRangeOverMerges(current.rows, range)
  const rowSpan = block.bottom - block.top + 1
  const colSpan = block.right - block.left + 1
  if (rowSpan === 1 && colSpan === 1) return { rows: current.rows }

  return {
    rows: current.rows.map((row, rowIndex) => {
      if (rowIndex < block.top || rowIndex > block.bottom) return row
      return {
        ...row,
        cells: row.cells.map((cell, colIndex) => {
          if (colIndex < block.left || colIndex > block.right) return cell
          if (rowIndex === block.top && colIndex === block.left) {
            return { ...cell, rowSpan, colSpan }
          }
          // Swallowed: emptied, and stripped of any span of its own so two
          // anchors can never claim the same cell.
          return { ...withoutSpan(cell), text: '' }
        }),
      }
    }),
  }
}

/** Split every merge `range` touches back into plain cells. The anchor keeps its text. */
export function unmergeTableCells(
  current: TableNodeData,
  range: TableCellRange
): Pick<TableNodeData, 'rows'> {
  const block = expandRangeOverMerges(current.rows, range)

  return {
    rows: current.rows.map((row, rowIndex) => {
      if (rowIndex < block.top || rowIndex > block.bottom) return row
      return {
        ...row,
        cells: row.cells.map((cell, colIndex) => {
          if (colIndex < block.left || colIndex > block.right) return cell
          if (cell.rowSpan === undefined && cell.colSpan === undefined) return cell
          return withoutSpan(cell)
        }),
      }
    }),
  }
}

/** Whether `range` covers more than one cell once merges are taken into account. */
export function rangeCoversSeveralCells(rows: TableRow[], range: TableCellRange): boolean {
  const block = expandRangeOverMerges(rows, range)
  return block.bottom > block.top || block.right > block.left
}

/** Whether `range` touches any merge, and so whether there is anything to unmerge. */
export function rangeContainsMerge(rows: TableRow[], range: TableCellRange): boolean {
  const block = expandRangeOverMerges(rows, range)
  for (let r = block.top; r <= block.bottom; r++) {
    for (let c = block.left; c <= block.right; c++) {
      const cell = rows[r]?.cells[c]
      if (cell && ((cell.rowSpan ?? 1) > 1 || (cell.colSpan ?? 1) > 1)) return true
    }
  }
  return false
}

/**
 * Which swatch the fill menu marks as current: the one colour every cell in the
 * selection carries, `'none'` when none of them is filled, or `'mixed'` when
 * they disagree.
 *
 * `'mixed'` matches no swatch, so a selection spanning two colours marks
 * neither rather than picking a winner — the same thing Sheets and Notion do,
 * and the only honest answer when the next click will overwrite both.
 */
export type TableFillSelection = TableCellFill | 'none' | 'mixed'

export function commonTableCellFill(
  rows: TableRow[],
  range: TableCellRange | null
): TableFillSelection {
  if (!range) return 'mixed'

  let common: TableCellFill | undefined
  let seenOne = false

  for (let row = range.top; row <= range.bottom; row++) {
    for (let col = range.left; col <= range.right; col++) {
      const fill = rows[row]?.cells[col]?.fill
      if (!seenOne) {
        common = fill
        seenOne = true
      } else if (fill !== common) {
        return 'mixed'
      }
    }
  }

  return seenOne ? (common ?? 'none') : 'mixed'
}

/**
 * Fill every cell in `range`; `undefined` clears them back to no fill.
 *
 * The fill is written into each cell rather than onto the row or column, so a
 * row inserted into a filled column arrives unfilled. That is visible, and the
 * alternative was resolving cell over column over row on every cell render and
 * giving 'clear this cell' two meanings.
 */
export function setTableCellFills(
  current: TableNodeData,
  range: TableCellRange,
  fill: TableCellFill | undefined
): Pick<TableNodeData, 'rows'> {
  return {
    rows: current.rows.map((row, ri) => {
      if (ri < range.top || ri > range.bottom) return row
      return {
        ...row,
        cells: row.cells.map((cell, ci) => {
          if (ci < range.left || ci > range.right) return cell
          if (fill) return { ...cell, fill }
          // Deleted rather than set to undefined, so a cleared cell serializes
          // to exactly what it was before it was ever filled. Copy-then-delete
          // rather than destructuring the key out, which would keep every other
          // field only by naming a rest binding nothing reads.
          const cleared = { ...cell }
          delete cleared.fill
          return cleared
        }),
      }
    }),
  }
}

/** Set the row count, growing with empty rows or truncating from the bottom. */
export function setTableRowCount(current: TableNodeData, count: number): Pick<TableNodeData, 'rows'> {
  const target = Math.max(1, Math.floor(count))
  const existing = current.rows.length

  if (target === existing) return { rows: current.rows }

  // Truncating cuts any merge that reached past the new last row.
  const kept =
    target < existing
      ? unmergeCutBy(current.rows, ({ row, rowSpan }) => row + rowSpan > target)
      : current.rows

  return {
    rows:
      target < existing
        ? kept.slice(0, target)
        : [
            ...kept,
            ...Array.from({ length: target - existing }, () => ({
              height: TABLE_DEFAULT_ROW_HEIGHT,
              cells: current.columnWidths.map(() => ({ text: '' })),
            })),
          ],
  }
}

/**
 * There is no upper bound on a table's size, deliberately: typing 200 rows makes
 * 200 rows. Nothing pays for that. Every cell is a rendered DOM node with no
 * virtualization, so a 20 x 200 table is 4000 elements the canvas walks on every
 * pan and zoom. If large tables turn out to be common, virtualize the cell grid
 * rather than reintroducing a limit.
 *
 * The lower bound of one column and one row is structural rather than policy: a
 * table with none has no cell to click and no way back.
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
  // Spec flow type; missing means `data` (read through `getFlowType`)
  flowType?: FlowType
  protocol?: Protocol
  port?: number
  dataClassification?: DataClassification[]
  encrypted?: boolean
  // Authentication methods on the spec list. The retired boolean
  // `authenticated` is gone; read the list through `getAuthentication` and
  // answer "is it authenticated" with `isAuthenticated` (plan I5).
  authentication?: AuthenticationType[]
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

// Trust Boundary edge types. The two lists sync to the boundary row's
// `authorization` and `authentication` (apps.diagrams.services), so their
// values are the spec's lists from types/domain.ts.
export type AccessControlMethod = AuthorizationType
export const ACCESS_CONTROL_METHODS: { value: AccessControlMethod; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'acl', label: 'ACL' },
  { value: 'rbac', label: 'RBAC' },
  { value: 'mac', label: 'MAC' },
  { value: 'dac', label: 'DAC' },
  { value: 'abac', label: 'ABAC' },
]

export type AuthenticationMethod = AuthenticationType
export const AUTHENTICATION_METHODS: { value: AuthenticationMethod; label: string }[] = AUTHENTICATION_TYPES

export interface TrustBoundaryEdgeData {
  label?: string
  // Spec boundary type; missing means `trust` (read through `getBoundaryType`)
  boundaryType?: BoundaryType
  accessControlMethods?: AccessControlMethod[]
  authenticationMethods?: AuthenticationMethod[]
  // Crossing requirements (Boundary.data_validation, logging, monitoring, rate_limit)
  dataValidation?: boolean
  logging?: boolean
  monitoring?: boolean
  rateLimit?: string
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
  // The flow types shown on the canvas (the "physical view" filter, plan
  // F22). Missing means every type is visible.
  visibleFlowTypes?: FlowType[]
}

// Diagram entity (DFDSerializer)
export interface Diagram {
  id: string
  name: string
  diagramType?: DiagramTypeValue
  isPrimary?: boolean
  // The blueprint the diagram belongs to; threatModel is derived from it
  blueprint?: number
  threatModel?: number
  canvasData?: CanvasData
  updatedBy?: string
  updatedByEmail?: string
  createdAt?: string
  updatedAt?: string
}

export interface CreateDiagramInput {
  threatModelId: string
  // The blueprint to create the diagram in; the model's default when omitted
  blueprintId?: number
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
