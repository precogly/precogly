import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useReactFlow, type Node, type NodeProps } from '@xyflow/react'
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  Plus,
  TableCellsMerge,
  TableCellsSplit,
  Trash2,
} from 'lucide-react'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { cn } from '@/lib/utils'
import { useTableDrag } from '../../hooks/useTableDrag'
import { useTableSelection } from '../../hooks/useTableSelection'
import {
  commonTableCellFill,
  mergeTableCells,
  rangeContainsMerge,
  rangeCoversSeveralCells,
  tableCoveredCells,
  unmergeTableCells,
  insertTableColumn,
  insertTableRow,
  removeTableColumn,
  removeTableRow,
  setTableCellFills,
  tableRangeContains,
  TABLE_FILL_COLORS,
  type DiagramNode,
  type TableCellFill,
  type TableCellRange,
  type TableNodeData,
} from '../../types'
import { TableActionButton, TableAxisGrip, TableFillSubmenu } from './table-chrome'
import { BUTTON, CORNERS, DIVIDER_HIT, GAP, HANDLE } from './table-chrome-sizes'

type TableNodeType = Node<TableNodeData, 'table'>

interface CellRef {
  row: number
  col: number
}

/**
 * Maximal runs of consecutive indices for which `blocked` is false, as
 * inclusive `[start, end]` pairs.
 *
 * Used to break a divider into the stretches it is allowed to occupy. A divider
 * spans the whole table, so where a merge crosses the boundary it would lie
 * across the middle of a merged cell and swallow clicks meant for it — a
 * two-row-tall merged cell has the row divider running through its centre,
 * which is exactly where a pointer lands.
 */
function openRuns(count: number, blocked: (index: number) => boolean): [number, number][] {
  const runs: [number, number][] = []
  let start: number | null = null

  for (let i = 0; i < count; i++) {
    if (blocked(i)) {
      if (start !== null) runs.push([start, i - 1])
      start = null
    } else if (start === null) {
      start = i
    }
  }
  if (start !== null) runs.push([start, count - 1])

  return runs
}

/** How far each arrow key steps the cell selection. */
const ARROW_STEPS: Record<string, { row: number; col: number } | undefined> = {
  ArrowUp: { row: -1, col: 0 },
  ArrowDown: { row: 1, col: 0 },
  ArrowLeft: { row: 0, col: -1 },
  ArrowRight: { row: 0, col: 1 },
}

/**
 * Size a cell's textarea to its content.
 *
 * Without this the textarea stays one line tall and scrolls internally while
 * being typed into, so a wrapping cell only grows once editing ends and the
 * plain span takes over — the row resizes a beat late. Setting height to auto
 * first lets scrollHeight shrink again on deletion.
 */
function fitToContent(element: HTMLTextAreaElement) {
  element.style.height = 'auto'
  element.style.height = `${element.scrollHeight}px`
}

export const TableNode = memo(function TableNode({ id, data, selected }: NodeProps<TableNodeType>) {
  const { setNodes } = useReactFlow<DiagramNode>()
  const [editing, setEditing] = useState<CellRef | null>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // One pass over the anchors per render rather than a flag on every cell; see
  // `TableCell`. Memoized because every cell asks it a question, and because the
  // selection hook holds on to `anchorOf`.
  const coveredCells = useMemo(() => tableCoveredCells(data.rows), [data.rows])
  const anchorOf = useCallback(
    (row: number, col: number) => coveredCells.get(`${row},${col}`) ?? { row, col },
    [coveredCells]
  )

  // Destructured rather than held as one object: the hook returns a fresh
  // object each render, so a callback depending on the whole thing would be
  // rebuilt every time even though the handlers inside it are stable.
  const {
    range: selectedRange,
    axis: selectedAxis,
    beginCellSelection,
    selectAxis,
    selectUnlessInside,
    moveFocus,
    clear: clearSelection,
  } = useTableSelection(id, data.rows.length, data.columnWidths.length, anchorOf)

  // Sizes come from the drag hook rather than straight from the data: while a
  // divider or corner is being dragged they are its live values, committed to
  // the graph once on pointerup.
  const { columnWidths, rowHeights, fontSize, draftOffset, beginResize, beginScale } =
    useTableDrag(id, data)

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
  //
  // Adjusting local state while rendering rather than in an effect is React's
  // answer for deriving state from a changed prop: an effect would paint once
  // without the caret, then again to place it.
  const [lastInlineFlag, setLastInlineFlag] = useState(data.isInlineEditing)
  if (lastInlineFlag !== data.isInlineEditing) {
    setLastInlineFlag(data.isInlineEditing)
    // Only a fallback for the flag arriving with no cell chosen, as it does on
    // a fresh drop. Never displaces a cell the user has already picked.
    if (data.isInlineEditing) setEditing((current) => current ?? { row: 0, col: 0 })
  }

  // Clearing the flag stays in an effect: it writes to the React Flow store,
  // which is a side effect on something outside this component.
  useEffect(() => {
    if (data.isInlineEditing) updateData(() => ({ isInlineEditing: false }))
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

  // Deselecting the node drops the cell selection with it, so a stale highlight
  // cannot outlive the table it belongs to. Same set-during-render pattern as
  // the caret above.
  const [lastSelected, setLastSelected] = useState(selected)
  if (lastSelected !== selected) {
    setLastSelected(selected)
    if (!selected) clearSelection()
  }

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

  const mergeCells = useCallback(
    (range: TableCellRange) => {
      setEditing(null)
      updateData((current) => mergeTableCells(current, range))
    },
    [updateData]
  )

  const unmergeCells = useCallback(
    (range: TableCellRange) => {
      setEditing(null)
      updateData((current) => unmergeTableCells(current, range))
    },
    [updateData]
  )

  const fillCells = useCallback(
    (range: TableCellRange, fill: TableCellFill | undefined) =>
      updateData((current) => setTableCellFills(current, range, fill)),
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
      clearSelection()
      updateData((current) => removeTableColumn(current, index))
    },
    [clearSelection, updateData]
  )
  const removeRow = useCallback(
    (index: number) => {
      setEditing(null)
      clearSelection()
      updateData((current) => removeTableRow(current, index))
    },
    [clearSelection, updateData]
  )

  // Delete removes a selected row or column. Guarded on `editing` so the key
  // deletes text, not structure, while a cell is open; the editor's own
  // shortcut never sees it either way, because the container stops the event.
  //
  // Only a grip selection has an `axis`, so Delete over a dragged range of cells
  // does nothing rather than guessing which structure to take out.
  const handleContainerKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (editing) return

      if (event.key === 'Escape' && selectedRange) {
        event.preventDefault()
        event.stopPropagation()
        clearSelection()
        return
      }

      // With a cell selected the arrows walk the selection; with none they are
      // left alone, so they still nudge the table the way they nudge any other
      // node. Stopping the event is what makes the difference — React Flow
      // moves the node from its own key handler on the wrapper above this one.
      const step = ARROW_STEPS[event.key]
      if (step && moveFocus(step.row, step.col, event.shiftKey)) {
        event.preventDefault()
        event.stopPropagation()
        return
      }

      if (!selectedAxis || !selectedRange) return
      if (event.key !== 'Delete' && event.key !== 'Backspace') return
      event.preventDefault()
      event.stopPropagation()
      if (selectedAxis === 'column') removeColumn(selectedRange.left)
      else removeRow(selectedRange.top)
    },
    [clearSelection, editing, moveFocus, removeColumn, removeRow, selectedAxis, selectedRange]
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
  // grow when its text wraps past it, which is Miro's rule. Dragging a row
  // divider above the content's own height therefore has no visible effect, and
  // scaling the table down cannot shrink a row below what its text needs. Miro
  // behaves the same way on both counts.
  //
  // A row's real height is not knowable from the data, so every per-row and
  // per-column control is a grid item in these same tracks rather than
  // something positioned from a running sum. Grips and dividers sit in a track
  // and push their visible part outside it, tracking the real geometry with no
  // measurement pass and no offsets to drift.

  const gridTemplateColumns = columnWidths.map((width) => `${width}px`).join(' ')
  const gridTemplateRows = rowHeights.map((height) => `minmax(${height}px, auto)`).join(' ')

  const singleColumn = data.columnWidths.length <= 1
  const singleRow = data.rows.length <= 1

  /** Insert, fill and delete entries for one cell, used by every right-click. */
  const cellMenuItems = (cell: CellRef) => {
    // What the menu acts on. Right-clicking outside the selection has already
    // moved it onto the clicked cell, and right-clicking a grip onto that row or
    // column, so the selection is what was aimed at. The fallback covers a menu
    // opened before anything is selected, which is the state a table is in until
    // its first click.
    const menuRange = selectedRange ?? {
      top: cell.row,
      bottom: cell.row,
      left: cell.col,
      right: cell.col,
    }

    return (
    <ContextMenuContent
      className="w-52"
      // Radix hands focus back to the menu's trigger on close, and does it after
      // the close animation rather than on the click. That is late enough to
      // land on a cell the user has already double-clicked into, pulling the
      // caret out of the textarea a beat after it appeared. The trigger is a
      // canvas cell with nothing to hand focus back to, so the table's own
      // container takes it instead — that is what the Delete and Escape
      // shortcuts listen on — and nothing takes it while a cell is open.
      onCloseAutoFocus={(event) => {
        event.preventDefault()
        if (!editing) containerRef.current?.focus()
      }}
    >
      <TableFillSubmenu
        current={commonTableCellFill(data.rows, menuRange)}
        onSelect={(fill) => fillCells(menuRange, fill)}
      />
      <ContextMenuSeparator />
      <ContextMenuItem
        disabled={!rangeCoversSeveralCells(data.rows, menuRange)}
        onSelect={() => mergeCells(menuRange)}
      >
        <TableCellsMerge />
        Merge cells
      </ContextMenuItem>
      <ContextMenuItem
        disabled={!rangeContainsMerge(data.rows, menuRange)}
        onSelect={() => unmergeCells(menuRange)}
      >
        <TableCellsSplit />
        Unmerge cells
      </ContextMenuItem>
      <ContextMenuSeparator />
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
  }

  // tabIndex on the container makes it a focus target, so that clicking a grip —
  // which focuses a button inside it — lets the Delete keydown bubble up to here.
  return (
    // No explicit size: the grid's own box is the table, so anything anchored to
    // the table's edges uses right/bottom/50% rather than a computed offset.
    <div
      ref={containerRef}
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
            // A cell under a merge is not rendered at all; the anchor's own box
            // spans the tracks it would have occupied.
            if (coveredCells.has(`${rowIndex},${colIndex}`)) return null

            // Clamped because a span that outgrew the grid would otherwise ask
            // the grid for tracks that do not exist. The structural helpers drop
            // such spans; this is the backstop.
            const colSpan = Math.min(cell.colSpan ?? 1, data.columnWidths.length - colIndex)
            const rowSpan = Math.min(cell.rowSpan ?? 1, data.rows.length - rowIndex)

            const isHeader = data.headerRow && rowIndex === 0
            const isEditing = editing?.row === rowIndex && editing.col === colIndex
            const inSelection = selectedRange
              ? tableRangeContains(selectedRange, rowIndex, colIndex)
              : false

            return (
              <ContextMenu key={`${rowIndex}-${colIndex}`}>
                <ContextMenuTrigger asChild>
                  <div
                    // Read back by the selection drag's hit test, which finds
                    // the cell under the pointer through the DOM rather than by
                    // measuring tracks whose heights it cannot know.
                    data-table-id={id}
                    data-table-cell={`${rowIndex},${colIndex}`}
                    onPointerDown={(event) => {
                      // Only once the node is selected. Before that a press on a
                      // cell belongs to React Flow, which drags the table the
                      // way it drags every other node.
                      if (!selected || isEditing) return
                      beginCellSelection(rowIndex, colIndex, event)
                    }}
                    onContextMenu={() => selectUnlessInside(rowIndex, colIndex)}
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
                    //
                    // An explicit fill beats the header row's tint: the tint is a
                    // default for the row, the fill is something the user chose
                    // for this cell.
                    style={{
                      fontSize,
                      gridColumn: `${colIndex + 1} / span ${colSpan}`,
                      gridRow: `${rowIndex + 1} / span ${rowSpan}`,
                      backgroundColor: cell.fill ? TABLE_FILL_COLORS[cell.fill] : undefined,
                    }}
                    className={cn(
                      'relative flex items-center border-slate-300 px-2 leading-tight text-slate-800',
                      colIndex + colSpan < row.cells.length && 'border-r',
                      rowIndex + rowSpan < data.rows.length && 'border-b',
                      isHeader && 'font-semibold',
                      isHeader && !cell.fill && 'bg-slate-100',
                      // What actually hands the press to the table rather than
                      // to React Flow, and only once the node is selected: an
                      // unselected table drags from its body like every other
                      // node. The `stopPropagation` in `beginCellSelection`
                      // cannot do this job — React Flow drags from a native
                      // listener on the node wrapper, which is an ancestor of
                      // this cell, so it has already run by the time React's
                      // synthetic handler fires at the root.
                      selected && !isEditing && 'nodrag'
                    )}
                  >
                    {/* The selection is an overlay rather than a background, so a
                        filled cell still shows its fill through it. Only the
                        outer edges of the range are outlined; a border on every
                        cell would repaint the table's own gridlines blue. */}
                    {inSelection && selectedRange && (
                      <div
                        className={cn(
                          'pointer-events-none absolute inset-0 border-blue-500 bg-blue-500/15',
                          rowIndex === selectedRange.top && 'border-t-2',
                          rowIndex === selectedRange.bottom && 'border-b-2',
                          colIndex === selectedRange.left && 'border-l-2',
                          colIndex === selectedRange.right && 'border-r-2'
                        )}
                      />
                    )}
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
                        // No `onMouseDown` stop: `nodrag` below stops the drag and
                        // no ancestor handles `mousedown`. See `beginCellSelection`
                        // for what a stop costs — not here, though: opening the
                        // menu blurs this textarea and unmounts it, so no layer is
                        // ever open over it.
                        // overflow-hidden so the growing textarea never shows a
                        // scrollbar; its height always matches its content, so
                        // nothing is hidden.
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
        {columnWidths.flatMap((_, index) =>
          // The trailing edge of the last column is the table's own, which no
          // merge can straddle; elsewhere, skip the rows where one does.
          openRuns(data.rows.length, (row) =>
            index + 1 < data.columnWidths.length ? anchorOf(row, index + 1).col <= index : false
          ).map(([from, to]) => (
            <div
              key={`col-divider-${index}-${from}`}
              className="pointer-events-none relative"
              style={{ gridColumn: index + 1, gridRow: `${from + 1} / ${to + 2}` }}
            >
              <div
                onPointerDown={(event) => beginResize('column', index, event)}
                className="nodrag nopan pointer-events-auto absolute inset-y-0 cursor-col-resize"
                style={{ right: -DIVIDER_HIT / 2, width: DIVIDER_HIT }}
              />
            </div>
          ))
        )}
        {rowHeights.map((_, index) =>
          openRuns(data.columnWidths.length, (col) =>
            index + 1 < data.rows.length ? anchorOf(index + 1, col).row <= index : false
          ).map(([from, to]) => (
            <div
              key={`row-divider-${index}-${from}`}
              className="pointer-events-none relative"
              style={{ gridRow: index + 1, gridColumn: `${from + 1} / ${to + 2}` }}
            >
              <div
                onPointerDown={(event) => beginResize('row', index, event)}
                className="nodrag nopan pointer-events-auto absolute inset-x-0 cursor-row-resize"
                style={{ bottom: -DIVIDER_HIT / 2, height: DIVIDER_HIT }}
              />
            </div>
          ))
        )}

        {/* Grips: one bar per column above the table and per row to its left.
            Clicking selects that row or column; right-clicking opens the same
            menu as a cell, anchored to the whole axis. */}
        {selected &&
          columnWidths.map((_, index) => (
            <TableAxisGrip
              key={`col-grip-${index}`}
              axis="column"
              index={index}
              selected={selectedAxis === 'column' && selectedRange?.left === index}
              deleteDisabled={singleColumn}
              onSelect={() => selectAxis('column', index)}
              onDelete={() => removeColumn(index)}
              menu={cellMenuItems({ row: 0, col: index })}
            />
          ))}

        {selected &&
          rowHeights.map((_, index) => (
            <TableAxisGrip
              key={`row-grip-${index}`}
              axis="row"
              index={index}
              selected={selectedAxis === 'row' && selectedRange?.top === index}
              deleteDisabled={singleRow}
              onSelect={() => selectAxis('row', index)}
              onDelete={() => removeRow(index)}
              menu={cellMenuItems({ row: index, col: 0 })}
            />
          ))}
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
          <TableActionButton
            onClick={() => insertColumn(data.columnWidths.length)}
            title="Add column"
            className="top-1/2 -translate-y-1/2"
            style={{ right: -(BUTTON + GAP) }}
          >
            <Plus className="h-3 w-3" />
          </TableActionButton>
          <TableActionButton
            onClick={() => insertRow(data.rows.length)}
            title="Add row"
            className="left-1/2 -translate-x-1/2"
            style={{ bottom: -(BUTTON + GAP) }}
          >
            <Plus className="h-3 w-3" />
          </TableActionButton>
        </>
      )}
    </div>
  )
})
