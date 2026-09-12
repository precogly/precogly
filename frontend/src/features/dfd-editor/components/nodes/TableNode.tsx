import { memo, useCallback, useEffect, useRef, useState } from 'react'
import { useReactFlow, type Node, type NodeProps } from '@xyflow/react'
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, GripVertical, Plus, Trash2 } from 'lucide-react'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { cn } from '@/lib/utils'
import {
  insertTableColumn,
  insertTableRow,
  removeTableColumn,
  removeTableRow,
  TABLE_DEFAULT_FONT_SIZE,
  TABLE_MIN_COLUMN_WIDTH,
  TABLE_MIN_FONT_SIZE,
  TABLE_MIN_ROW_HEIGHT,
  type DiagramNode,
  type TableNodeData,
} from '../../types'

type TableNodeType = Node<TableNodeData, 'table'>

interface CellRef {
  row: number
  col: number
}

/** Which row or column the grips have selected, if any. */
type AxisSelection = { axis: 'row' | 'column'; index: number } | null

/** Thickness of the hit area for a divider drag. */
const DIVIDER_HIT = 7
/**
 * Thickness of the row and column grips. Notion and FigJam both put the
 * row/column controls on a bar spanning the whole edge rather than a small
 * target, because aiming at a thin invisible strip is the part people miss.
 */
const GRIP = 18
/** Side of the square corner handles that scale the whole table. */
const HANDLE = 8

/**
 * Size a cell's textarea to its content.
 *
 * Without this the textarea stays one line tall and scrolls internally while
 * being typed into, so a wrapping cell only grows once editing ends and the
 * plain span takes over — the row appears to resize a beat late. Setting height
 * to auto first is what lets scrollHeight shrink again on deletion.
 */
function fitToContent(element: HTMLTextAreaElement) {
  element.style.height = 'auto'
  element.style.height = `${element.scrollHeight}px`
}

const CORNERS = [
  { corner: 'nw', cursor: 'cursor-nwse-resize', style: (h: number) => ({ left: -h / 2, top: -h / 2 }) },
  { corner: 'ne', cursor: 'cursor-nesw-resize', style: (h: number) => ({ right: -h / 2, top: -h / 2 }) },
  { corner: 'se', cursor: 'cursor-nwse-resize', style: (h: number) => ({ right: -h / 2, bottom: -h / 2 }) },
  { corner: 'sw', cursor: 'cursor-nesw-resize', style: (h: number) => ({ left: -h / 2, bottom: -h / 2 }) },
] as const

export const TableNode = memo(function TableNode({ id, data, selected }: NodeProps<TableNodeType>) {
  const { setNodes, getZoom } = useReactFlow<DiagramNode>()
  const [editing, setEditing] = useState<CellRef | null>(null)
  const [axisSelection, setAxisSelection] = useState<AxisSelection>(null)

  // While a divider is being dragged the sizes live here rather than in node
  // data. Writing every pointermove into the graph would rewrite all nodes on
  // each frame and push one undo entry per pixel; the drag commits once on
  // pointerup, which is also one undo step.
  const [draftSizes, setDraftSizes] = useState<{
    columnWidths: number[]
    rowHeights: number[]
    fontSize?: number
  } | null>(null)

  /**
   * Live offset while a top or left corner is being dragged.
   *
   * Growing from those corners moves the node's origin, but writing
   * `node.position` on every frame would push an undo entry per pixel, the same
   * problem the size draft avoids. So the node is translated visually during the
   * drag and its real position is written once on pointerup.
   */
  const [draftOffset, setDraftOffset] = useState<{ x: number; y: number } | null>(null)

  const inputRef = useRef<HTMLTextAreaElement>(null)

  const columnWidths = draftSizes?.columnWidths ?? data.columnWidths
  const rowHeights = draftSizes?.rowHeights ?? data.rows.map((row) => row.height)
  const fontSize = draftSizes?.fontSize ?? data.fontSize ?? TABLE_DEFAULT_FONT_SIZE

  const updateData = useCallback(
    (mutate: (current: TableNodeData) => Partial<TableNodeData>) => {
      setNodes((nodes) =>
        nodes.map((node) =>
          node.id === id
            ? { ...node, data: { ...node.data, ...mutate(node.data as TableNodeData) } }
            : node
        )
      )
    },
    [id, setNodes]
  )

  // A freshly dropped table is handed the same isInlineEditing flag every other
  // node type gets (see useHandleDrop); for a table that means "put the caret in
  // the first cell".
  useEffect(() => {
    if (!data.isInlineEditing) return
    updateData(() => ({ isInlineEditing: false }))
    // Only a fallback for the flag arriving with no cell chosen, as it does on
    // a fresh drop. Never displaces a cell the user has already picked.
    setEditing((current) => current ?? { row: 0, col: 0 })
  }, [data.isInlineEditing, updateData])

  useEffect(() => {
    if (editing) {
      requestAnimationFrame(() => {
        if (!inputRef.current) return
        // Size before focusing, so opening a cell that already holds wrapped
        // text does not start one line tall and then jump.
        fitToContent(inputRef.current)
        inputRef.current.focus()
        inputRef.current.select()
      })
    }
  }, [editing])

  // Deselecting the node drops the row/column selection with it, so a stale
  // highlight cannot outlive the grips that produced it.
  useEffect(() => {
    if (!selected) setAxisSelection(null)
  }, [selected])

  // Cell contents

  const setCellText = useCallback(
    (row: number, col: number, text: string) => {
      updateData((current) => ({
        rows: current.rows.map((r, ri) =>
          ri !== row
            ? r
            : { ...r, cells: r.cells.map((cell, ci) => (ci !== col ? cell : { ...cell, text })) }
        ),
      }))
    },
    [updateData]
  )

  // Structure

  const insertColumn = useCallback(
    (index: number) => updateData((current) => insertTableColumn(current, index)),
    [updateData]
  )
  const insertRow = useCallback(
    (index: number) => updateData((current) => insertTableRow(current, index)),
    [updateData]
  )
  const removeColumn = useCallback(
    (index: number) => {
      setEditing(null)
      setAxisSelection(null)
      updateData((current) => removeTableColumn(current, index))
    },
    [updateData]
  )
  const removeRow = useCallback(
    (index: number) => {
      setEditing(null)
      setAxisSelection(null)
      updateData((current) => removeTableRow(current, index))
    },
    [updateData]
  )

  // Delete removes a selected row or column. Guarded on `editing` so the key
  // deletes text, not structure, while a cell is open; the editor's own
  // shortcut never sees it either way, because the container stops the event.
  const handleContainerKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (editing || !axisSelection) return
      if (event.key !== 'Delete' && event.key !== 'Backspace') return
      event.preventDefault()
      event.stopPropagation()
      if (axisSelection.axis === 'column') removeColumn(axisSelection.index)
      else removeRow(axisSelection.index)
    },
    [axisSelection, editing, removeColumn, removeRow]
  )

  // Resizing

  const beginResize = useCallback(
    (axis: 'column' | 'row', index: number, event: React.PointerEvent) => {
      event.stopPropagation()
      event.preventDefault()

      const startCoord = axis === 'column' ? event.clientX : event.clientY
      const startColumnWidths = [...data.columnWidths]
      const startRowHeights = data.rows.map((row) => row.height)
      // Pointer deltas arrive in screen pixels but sizes are stored in diagram
      // coordinates, so a drag at 50% zoom must move the divider twice as far in
      // the data as it moved on screen.
      const zoom = getZoom()

      let latest = { columnWidths: startColumnWidths, rowHeights: startRowHeights }

      const handleMove = (moveEvent: PointerEvent) => {
        const delta = ((axis === 'column' ? moveEvent.clientX : moveEvent.clientY) - startCoord) / zoom
        latest =
          axis === 'column'
            ? {
                columnWidths: startColumnWidths.map((width, ci) =>
                  ci === index ? Math.max(TABLE_MIN_COLUMN_WIDTH, width + delta) : width
                ),
                rowHeights: startRowHeights,
              }
            : {
                columnWidths: startColumnWidths,
                rowHeights: startRowHeights.map((height, ri) =>
                  ri === index ? Math.max(TABLE_MIN_ROW_HEIGHT, height + delta) : height
                ),
              }
        setDraftSizes(latest)
      }

      const handleUp = () => {
        window.removeEventListener('pointermove', handleMove)
        window.removeEventListener('pointerup', handleUp)
        setDraftSizes(null)
        updateData((current) => ({
          columnWidths: latest.columnWidths,
          rows: current.rows.map((row, ri) => ({ ...row, height: latest.rowHeights[ri] })),
        }))
      }

      window.addEventListener('pointermove', handleMove)
      window.addEventListener('pointerup', handleUp)
    },
    [data.columnWidths, data.rows, getZoom, updateData]
  )

  /**
   * Corner drag: scales every column and row by one factor per axis, so the
   * table grows as a whole and keeps its proportions. Dragging a left or top
   * corner also moves the node's origin, since the opposite edge is what stays
   * put.
   *
   * The floor is one minimum-width column per column, which is why the clamp is
   * on the total rather than per column — clamping each one separately would
   * distort the proportions as soon as any single column hit the floor.
   */
  const beginScale = useCallback(
    (corner: 'nw' | 'ne' | 'se' | 'sw', event: React.PointerEvent) => {
      event.stopPropagation()
      event.preventDefault()

      const startX = event.clientX
      const startY = event.clientY
      const startColumnWidths = [...data.columnWidths]
      const startRowHeights = data.rows.map((row) => row.height)
      const startWidth = startColumnWidths.reduce((sum, width) => sum + width, 0)
      const startHeight = startRowHeights.reduce((sum, height) => sum + height, 0)
      const minWidth = startColumnWidths.length * TABLE_MIN_COLUMN_WIDTH
      const minHeight = startRowHeights.length * TABLE_MIN_ROW_HEIGHT
      const zoom = getZoom()

      const growsLeft = corner === 'nw' || corner === 'sw'
      const growsUp = corner === 'nw' || corner === 'ne'

      const startFontSize = data.fontSize ?? TABLE_DEFAULT_FONT_SIZE

      let latestSizes = { columnWidths: startColumnWidths, rowHeights: startRowHeights }
      let latestOffset = { x: 0, y: 0 }
      let latestFontSize = startFontSize

      const handleMove = (moveEvent: PointerEvent) => {
        const dx = (moveEvent.clientX - startX) / zoom
        const dy = (moveEvent.clientY - startY) / zoom

        let width = Math.max(minWidth, growsLeft ? startWidth - dx : startWidth + dx)
        let height = Math.max(minHeight, growsUp ? startHeight - dy : startHeight + dy)

        // Shift scales uniformly and takes the text with it, as Miro does; a
        // plain drag stretches the axes independently and leaves text alone.
        // Read per move rather than at pointerdown, so shift can be pressed or
        // released mid-drag.
        if (moveEvent.shiftKey) {
          const uniform = Math.max(width / startWidth, height / startHeight)
          width = Math.max(minWidth, startWidth * uniform)
          height = Math.max(minHeight, startHeight * uniform)
          latestFontSize = Math.max(TABLE_MIN_FONT_SIZE, startFontSize * uniform)
        } else {
          latestFontSize = startFontSize
        }

        const scaleX = width / startWidth
        const scaleY = height / startHeight

        latestSizes = {
          columnWidths: startColumnWidths.map((columnWidth) => columnWidth * scaleX),
          rowHeights: startRowHeights.map((rowHeight) => rowHeight * scaleY),
        }
        // Derived from the clamped size rather than the raw pointer delta, so a
        // drag past the minimum stops moving the node instead of sliding it.
        latestOffset = {
          x: growsLeft ? startWidth - width : 0,
          y: growsUp ? startHeight - height : 0,
        }

        setDraftSizes({ ...latestSizes, fontSize: latestFontSize })
        setDraftOffset(latestOffset)
      }

      const handleUp = () => {
        window.removeEventListener('pointermove', handleMove)
        window.removeEventListener('pointerup', handleUp)
        setDraftSizes(null)
        setDraftOffset(null)
        setNodes((nodes) =>
          nodes.map((node) =>
            node.id === id
              ? {
                  ...node,
                  position: {
                    x: node.position.x + latestOffset.x,
                    y: node.position.y + latestOffset.y,
                  },
                  data: {
                    ...node.data,
                    columnWidths: latestSizes.columnWidths,
                    fontSize: latestFontSize,
                    rows: (node.data as TableNodeData).rows.map((row, ri) => ({
                      ...row,
                      height: latestSizes.rowHeights[ri],
                    })),
                  },
                }
              : node
          )
        )
      }

      window.addEventListener('pointermove', handleMove)
      window.addEventListener('pointerup', handleUp)
    },
    [data.columnWidths, data.fontSize, data.rows, getZoom, id, setNodes]
  )

  // Keyboard navigation between cells

  const handleCellKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLTextAreaElement>, cell: CellRef) => {
      // The editor deletes the selected node on Delete/Backspace and has
      // single-key tool shortcuts; without this the table vanishes mid-word.
      event.stopPropagation()

      const lastCol = data.columnWidths.length - 1
      const lastRow = data.rows.length - 1

      if (event.key === 'Escape') {
        setEditing(null)
      } else if (event.key === 'Tab') {
        event.preventDefault()
        if (event.shiftKey) {
          if (cell.col > 0) setEditing({ row: cell.row, col: cell.col - 1 })
          else if (cell.row > 0) setEditing({ row: cell.row - 1, col: lastCol })
        } else {
          if (cell.col < lastCol) setEditing({ row: cell.row, col: cell.col + 1 })
          else if (cell.row < lastRow) setEditing({ row: cell.row + 1, col: 0 })
        }
      } else if (event.key === 'Enter') {
        // Now that the cell is a textarea it can hold a deliberate line break;
        // shift-enter inserts one and plain enter keeps moving down the column.
        if (event.shiftKey) return
        event.preventDefault()
        if (cell.row < lastRow) setEditing({ row: cell.row + 1, col: cell.col })
        else setEditing(null)
      }
    },
    [data.columnWidths.length, data.rows.length]
  )

  // Layout
  //
  // A stored row height is a floor, not a height: `minmax(h, auto)` lets a row
  // grow when its text wraps past it, which is Miro's rule. Two consequences
  // worth knowing, both of which Miro shares — dragging a row divider above the
  // content's own height has no visible effect, and scaling the table down
  // cannot shrink a row below what its text needs.
  //
  // Because a row's real height is therefore not knowable from the data, every
  // per-row and per-column control is a grid item in these same tracks rather
  // than something positioned from a running sum. Grips and dividers place
  // themselves in a track and push their visible part outside it with absolute
  // positioning, so they track the real geometry with no measurement pass and
  // no offsets to drift.

  const gridTemplateColumns = columnWidths.map((width) => `${width}px`).join(' ')
  const gridTemplateRows = rowHeights.map((height) => `minmax(${height}px, auto)`).join(' ')

  const singleColumn = data.columnWidths.length <= 1
  const singleRow = data.rows.length <= 1

  /** Insert and delete entries for one cell, used by every cell's right-click. */
  const cellMenuItems = (cell: CellRef) => (
    <ContextMenuContent className="w-52">
      <ContextMenuItem onSelect={() => insertRow(cell.row)}>
        <ArrowUp />
        Insert row above
      </ContextMenuItem>
      <ContextMenuItem onSelect={() => insertRow(cell.row + 1)}>
        <ArrowDown />
        Insert row below
      </ContextMenuItem>
      <ContextMenuSeparator />
      <ContextMenuItem onSelect={() => insertColumn(cell.col)}>
        <ArrowLeft />
        Insert column left
      </ContextMenuItem>
      <ContextMenuItem onSelect={() => insertColumn(cell.col + 1)}>
        <ArrowRight />
        Insert column right
      </ContextMenuItem>
      <ContextMenuSeparator />
      <ContextMenuItem
        variant="destructive"
        disabled={singleRow}
        onSelect={() => removeRow(cell.row)}
      >
        <Trash2 />
        Delete row
      </ContextMenuItem>
      <ContextMenuItem
        variant="destructive"
        disabled={singleColumn}
        onSelect={() => removeColumn(cell.col)}
      >
        <Trash2 />
        Delete column
      </ContextMenuItem>
    </ContextMenuContent>
  )

  // tabIndex on the container makes it a focus target, so that clicking a grip —
  // which focuses a button inside it — lets the Delete keydown bubble up to here.
  return (
    // No explicit size: the grid's own box is the table, so anything anchored to
    // the table's edges uses right/bottom/50% rather than a computed offset.
    <div
      // w-fit rather than inline-block: an inline-block box carries baseline
      // descender space, which React Flow would measure as extra node height.
      className="relative w-fit"
      style={{
        transform: draftOffset ? `translate(${draftOffset.x}px, ${draftOffset.y}px)` : undefined,
      }}
      tabIndex={-1}
      onKeyDown={handleContainerKeyDown}
    >
      {/* Overflow stays visible: the grips and dividers are items in this grid
          whose visible parts sit outside its box, and hidden would clip them. */}
      <div
        className={cn(
          'grid rounded-sm border border-slate-400 bg-white',
          selected && 'ring-2 ring-blue-400'
        )}
        style={{ gridTemplateColumns, gridTemplateRows }}
      >
        {data.rows.map((row, rowIndex) =>
          row.cells.map((cell, colIndex) => {
            const isHeader = data.headerRow && rowIndex === 0
            const isEditing = editing?.row === rowIndex && editing.col === colIndex
            const inSelectedAxis =
              (axisSelection?.axis === 'column' && axisSelection.index === colIndex) ||
              (axisSelection?.axis === 'row' && axisSelection.index === rowIndex)

            return (
              <ContextMenu key={`${rowIndex}-${colIndex}`}>
                <ContextMenuTrigger asChild>
                  <div
                    onDoubleClick={(event) => {
                      // Must not reach React Flow's onNodeDoubleClick, which sets
                      // isInlineEditing on the node — the effect above reads that
                      // as "start in the first cell" and would override this one.
                      event.stopPropagation()
                      setEditing({ row: rowIndex, col: colIndex })
                    }}
                    // Placed explicitly rather than auto-placed. The dividers and
                    // grips are grid items with definite positions, and a column
                    // divider spans `1 / -1` of its column — between them they
                    // claim every defined cell, so auto-placed cells would be
                    // pushed into implicit rows below the table.
                    style={{ fontSize, gridColumn: colIndex + 1, gridRow: rowIndex + 1 }}
                    className={cn(
                      'flex items-center border-slate-300 px-2 leading-tight text-slate-800',
                      colIndex < row.cells.length - 1 && 'border-r',
                      rowIndex < data.rows.length - 1 && 'border-b',
                      isHeader && 'bg-slate-100 font-semibold',
                      inSelectedAxis && 'bg-blue-100'
                    )}
                  >
                    {isEditing ? (
                      // A textarea rather than an input so that editing wraps the
                      // way the rendered cell does; an input would put long text
                      // on one scrolling line and the cell would appear to change
                      // shape on every double-click.
                      <textarea
                        ref={inputRef}
                        rows={1}
                        value={cell.text}
                        onChange={(event) => {
                          fitToContent(event.target)
                          setCellText(rowIndex, colIndex, event.target.value)
                        }}
                        onKeyDown={(event) =>
                          handleCellKeyDown(event, { row: rowIndex, col: colIndex })
                        }
                        onBlur={() => setEditing(null)}
                        onMouseDown={(event) => event.stopPropagation()}
                        // overflow-hidden so the growing textarea never shows a
                        // scrollbar of its own; its height always matches content.
                        className="nodrag nopan nowheel w-full resize-none overflow-hidden bg-transparent text-[length:inherit] leading-tight outline-none"
                      />
                    ) : (
                      <span className="w-full whitespace-pre-wrap break-words">{cell.text}</span>
                    )}
                  </div>
                </ContextMenuTrigger>
                {cellMenuItems({ row: rowIndex, col: colIndex })}
              </ContextMenu>
            )
          })
        )}

        {/* Divider targets: each is a grid item spanning its own column (or row)
            across every row (or column), with the hit area straddling that
            track's trailing edge. Placing them in the grid is what lets a row
            grow with its content without the divider drifting off it. */}
        {columnWidths.map((_, index) => (
          <div
            key={`col-divider-${index}`}
            className="pointer-events-none relative"
            style={{ gridColumn: index + 1, gridRow: '1 / -1' }}
          >
            <div
              onPointerDown={(event) => beginResize('column', index, event)}
              className="nodrag nopan pointer-events-auto absolute inset-y-0 cursor-col-resize"
              style={{ right: -DIVIDER_HIT / 2, width: DIVIDER_HIT }}
            />
          </div>
        ))}
        {rowHeights.map((_, index) => (
          <div
            key={`row-divider-${index}`}
            className="pointer-events-none relative"
            style={{ gridRow: index + 1, gridColumn: '1 / -1' }}
          >
            <div
              onPointerDown={(event) => beginResize('row', index, event)}
              className="nodrag nopan pointer-events-auto absolute inset-x-0 cursor-row-resize"
              style={{ bottom: -DIVIDER_HIT / 2, height: DIVIDER_HIT }}
            />
          </div>
        ))}

        {/* Grips: one bar per column above the table and per row to its left.
            Drawn rather than revealed on hover, so there is something to aim at.
            Clicking selects that row or column; right-clicking opens the same
            menu as a cell, anchored to the whole axis.

            Each sits in its own track and pushes its visible bar outside the
            grid with `bottom: 100%` / `right: 100%`, so a grip always spans
            exactly the row or column it controls however tall that has grown. */}
        {selected &&
          columnWidths.map((_, index) => {
            const isSelected = axisSelection?.axis === 'column' && axisSelection.index === index
            return (
              <div
                key={`col-grip-${index}`}
                className="pointer-events-none relative"
                style={{ gridColumn: index + 1, gridRow: 1 }}
              >
                <ContextMenu>
                  <ContextMenuTrigger asChild>
                    <button
                      onPointerDown={(event) => event.stopPropagation()}
                      onClick={() => setAxisSelection({ axis: 'column', index })}
                      title={`Column ${index + 1}`}
                      className={cn(
                        'nodrag nopan pointer-events-auto absolute inset-x-0 flex items-center justify-center rounded-t-sm border border-b-0 text-slate-400',
                        isSelected
                          ? 'border-blue-400 bg-blue-100 text-blue-600'
                          : 'border-slate-300 bg-slate-100 hover:bg-slate-200 hover:text-slate-600'
                      )}
                      style={{ bottom: '100%', height: GRIP }}
                    >
                      <GripVertical className="h-3 w-3 rotate-90" />
                    </button>
                  </ContextMenuTrigger>
                  {cellMenuItems({ row: 0, col: index })}
                </ContextMenu>
                {isSelected && (
                  <button
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={() => removeColumn(index)}
                    disabled={singleColumn}
                    title="Delete column"
                    className="nodrag nopan pointer-events-auto absolute left-1/2 flex h-[18px] w-[18px] -translate-x-1/2 items-center justify-center rounded-sm border border-slate-300 bg-white text-slate-500 shadow-sm hover:bg-red-50 hover:text-red-600 disabled:opacity-40"
                    style={{ bottom: `calc(100% + ${GRIP + 6}px)` }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                )}
              </div>
            )
          })}

        {selected &&
          rowHeights.map((_, index) => {
            const isSelected = axisSelection?.axis === 'row' && axisSelection.index === index
            return (
              <div
                key={`row-grip-${index}`}
                className="pointer-events-none relative"
                style={{ gridRow: index + 1, gridColumn: 1 }}
              >
                <ContextMenu>
                  <ContextMenuTrigger asChild>
                    <button
                      onPointerDown={(event) => event.stopPropagation()}
                      onClick={() => setAxisSelection({ axis: 'row', index })}
                      title={`Row ${index + 1}`}
                      className={cn(
                        'nodrag nopan pointer-events-auto absolute inset-y-0 flex items-center justify-center rounded-l-sm border border-r-0 text-slate-400',
                        isSelected
                          ? 'border-blue-400 bg-blue-100 text-blue-600'
                          : 'border-slate-300 bg-slate-100 hover:bg-slate-200 hover:text-slate-600'
                      )}
                      style={{ right: '100%', width: GRIP }}
                    >
                      <GripVertical className="h-3 w-3" />
                    </button>
                  </ContextMenuTrigger>
                  {cellMenuItems({ row: index, col: 0 })}
                </ContextMenu>
                {isSelected && (
                  <button
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={() => removeRow(index)}
                    disabled={singleRow}
                    title="Delete row"
                    className="nodrag nopan pointer-events-auto absolute top-1/2 flex h-[18px] w-[18px] -translate-y-1/2 items-center justify-center rounded-sm border border-slate-300 bg-white text-slate-500 shadow-sm hover:bg-red-50 hover:text-red-600 disabled:opacity-40"
                    style={{ right: `calc(100% + ${GRIP + 6}px)` }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                )}
              </div>
            )
          })}
      </div>

      {selected && (
        <>
          {/* Corner handles scale the whole table. Placed last so they sit above
              the column and row dividers, whose drag targets reach the corners
              too and would otherwise swallow the press. */}
          {CORNERS.map(({ corner, cursor, style }) => (
            <div
              key={corner}
              onPointerDown={(event) => beginScale(corner, event)}
              className={cn(
                'nodrag nopan absolute z-10 rounded-[2px] border border-blue-400 bg-white',
                cursor
              )}
              style={{ width: HANDLE, height: HANDLE, ...style(HANDLE) }}
            />
          ))}

          {/* Append affordances, distinct from the menu's insert-at-position.
              Anchored to the container's own edges, so they need no dimensions:
              the container is exactly the table. */}
          <button
            onPointerDown={(event) => event.stopPropagation()}
            onClick={() => insertColumn(data.columnWidths.length)}
            title="Add column"
            className="nodrag nopan absolute top-1/2 -right-[22px] flex h-[18px] w-[18px] -translate-y-1/2 items-center justify-center rounded-sm border border-slate-300 bg-white text-slate-500 shadow-sm hover:bg-slate-100 hover:text-slate-800"
          >
            <Plus className="h-3 w-3" />
          </button>
          <button
            onPointerDown={(event) => event.stopPropagation()}
            onClick={() => insertRow(data.rows.length)}
            title="Add row"
            className="nodrag nopan absolute -bottom-[22px] left-1/2 flex h-[18px] w-[18px] -translate-x-1/2 items-center justify-center rounded-sm border border-slate-300 bg-white text-slate-500 shadow-sm hover:bg-slate-100 hover:text-slate-800"
          >
            <Plus className="h-3 w-3" />
          </button>
        </>
      )}
    </div>
  )
})
