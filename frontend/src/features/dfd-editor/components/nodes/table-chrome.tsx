import { useRef, type ReactNode, type CSSProperties } from 'react'
import { Ban, GripVertical, PaintBucket, Trash2 } from 'lucide-react'
import {
  ContextMenu,
  ContextMenuItem,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { cn } from '@/lib/utils'
import { TABLE_DRAG_THRESHOLD } from '../../hooks/useTableSelection'
import {
  TABLE_FILL_COLORS,
  TABLE_FILL_NAMES,
  type TableCellFill,
  type TableFillSelection,
} from '../../types'
import { BUTTON, GAP, GRIP } from './table-chrome-sizes'

/**
 * The small pieces of a table node that are presentation over a callback: the
 * grips that select a row or column, the buttons that add and remove them, and
 * the fill swatches its menus offer. Keeping them here leaves TableNode as the
 * state and the wiring.
 *
 * The row and column variants of the grip differ only by axis, so they are one
 * component — two would let a fix land in the column version and miss the row
 * one.
 */

/**
 * The small square buttons that sit outside the table: append a row or column,
 * delete the selected one.
 *
 * `pointer-events-auto` because several of these live inside grid items that
 * are `pointer-events-none` — those items exist to occupy a track, not to
 * intercept clicks meant for the cell beneath.
 */
export function TableActionButton({
  onClick,
  title,
  disabled,
  destructive,
  className,
  style,
  children,
}: {
  onClick: () => void
  title: string
  disabled?: boolean
  destructive?: boolean
  className?: string
  style?: CSSProperties
  children: ReactNode
}) {
  return (
    <button
      onPointerDown={(event) => event.stopPropagation()}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={cn(
        'nodrag nopan pointer-events-auto absolute flex items-center justify-center rounded-sm border border-slate-300 bg-white text-slate-500 shadow-sm disabled:opacity-40',
        destructive ? 'hover:bg-red-50 hover:text-red-600' : 'hover:bg-slate-100 hover:text-slate-800',
        className
      )}
      style={{ width: BUTTON, height: BUTTON, ...style }}
    >
      {children}
    </button>
  )
}

/**
 * One row or column grip: a bar spanning that whole row or column, drawn rather
 * than revealed on hover so there is something to aim at.
 *
 * The grip is a grid item in its own track, pushing its visible bar outside the
 * grid with `bottom: 100%` (columns) or `right: 100%` (rows). It therefore stays
 * aligned with a row that has grown past its stored height, with no offset to
 * recompute.
 */
export function TableAxisGrip({
  axis,
  index,
  selected,
  deleteDisabled,
  onSelect,
  onDelete,
  menu,
}: {
  axis: 'row' | 'column'
  index: number
  selected: boolean
  deleteDisabled: boolean
  onSelect: () => void
  onDelete: () => void
  menu: ReactNode
}) {
  const isColumn = axis === 'column'
  const label = isColumn ? 'Column' : 'Row'

  // Where the press started, to tell a click apart from a drag of the node.
  const pressRef = useRef<{ x: number; y: number } | null>(null)

  return (
    <div
      className="pointer-events-none relative"
      style={isColumn ? { gridColumn: index + 1, gridRow: 1 } : { gridRow: index + 1, gridColumn: 1 }}
    >
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <button
            // The press is deliberately left to bubble, and `nodrag` is absent,
            // so React Flow turns it into a node drag. The grips are how a
            // selected table is moved: its cells select instead of dragging it.
            onPointerDown={(event) => {
              if (event.button !== 0) return
              pressRef.current = { x: event.clientX, y: event.clientY }
            }}
            // Selection happens on pointerup rather than click because a drag
            // may or may not suppress the click that follows it, depending on
            // what React Flow's drag implementation does. pointerup always fires.
            onPointerUp={(event) => {
              const press = pressRef.current
              pressRef.current = null
              if (!press) return
              const moved =
                Math.abs(event.clientX - press.x) >= TABLE_DRAG_THRESHOLD ||
                Math.abs(event.clientY - press.y) >= TABLE_DRAG_THRESHOLD
              if (!moved) onSelect()
            }}
            // A right-click never runs the pointerup path above, so the axis is
            // selected here instead. Without it the menu's Fill would act on
            // whatever was selected before, not the row that was aimed at.
            onContextMenu={onSelect}
            title={`${label} ${index + 1}`}
            className={cn(
              'nopan pointer-events-auto absolute flex items-center justify-center border text-slate-400',
              isColumn ? 'inset-x-0 rounded-t-sm border-b-0' : 'inset-y-0 rounded-l-sm border-r-0',
              selected
                ? 'border-blue-400 bg-blue-100 text-blue-600'
                : 'border-slate-300 bg-slate-100 hover:bg-slate-200 hover:text-slate-600'
            )}
            style={isColumn ? { bottom: '100%', height: GRIP } : { right: '100%', width: GRIP }}
          >
            <GripVertical className={cn('h-3 w-3', isColumn && 'rotate-90')} />
          </button>
        </ContextMenuTrigger>
        {menu}
      </ContextMenu>

      {selected && (
        <TableActionButton
          onClick={onDelete}
          disabled={deleteDisabled}
          destructive
          title={`Delete ${axis}`}
          className={isColumn ? 'left-1/2 -translate-x-1/2' : 'top-1/2 -translate-y-1/2'}
          // Clears the edge of the track, then the grip sitting beyond it.
          style={
            isColumn
              ? { bottom: `calc(100% + ${GRIP + GAP}px)` }
              : { right: `calc(100% + ${GRIP + GAP}px)` }
          }
        >
          <Trash2 className="h-3 w-3" />
        </TableActionButton>
      )}
    </div>
  )
}

/**
 * The Fill entry both the cell menu and the grip menu carry: a row of swatches
 * plus a "no fill" one.
 *
 * Swatches rather than named rows because the name of a tint carries less than
 * the tint does, and a horizontal strip keeps the parent menu from growing by
 * six entries.
 */
export function TableFillSubmenu({
  current,
  onSelect,
}: {
  current: TableFillSelection
  onSelect: (fill: TableCellFill | undefined) => void
}) {
  return (
    <ContextMenuSub>
      {/* gap-2 here rather than in the primitive: shadcn's sub-trigger carries
          no gap because it normally holds only a label, and this is the one
          that also has an icon. */}
      <ContextMenuSubTrigger className="gap-2">
        <PaintBucket />
        Fill
      </ContextMenuSubTrigger>
      <ContextMenuSubContent className="flex min-w-0 gap-1 p-1">
        <FillSwatch
          label="No fill"
          selected={current === 'none'}
          onSelect={() => onSelect(undefined)}
        />
        {TABLE_FILL_NAMES.map((name) => (
          <FillSwatch
            key={name}
            label={name[0].toUpperCase() + name.slice(1)}
            color={TABLE_FILL_COLORS[name]}
            selected={current === name}
            onSelect={() => onSelect(name)}
          />
        ))}
      </ContextMenuSubContent>
    </ContextMenuSub>
  )
}

/**
 * One swatch.
 *
 * The background is an inline style so it beats the menu item's own
 * `focus:bg-accent`, which would otherwise repaint the swatch grey exactly when
 * it is being aimed at.
 *
 * Current-ness is a ring rather than a tick inside the square, which is what
 * Sheets draws. The "no fill" swatch already holds an icon, so a tick would
 * need a special case at the one place it matters most — telling "this cell is
 * unfilled" apart from "nothing is chosen". One ring covers all nine.
 *
 * `role`/`aria-checked` rather than Radix's RadioItem: these are one-of-nine,
 * so a screen reader should hear which is set, but RadioItem hard-codes an
 * indicator dot and the left padding to clear it, neither of which survives a
 * 24px square.
 */
function FillSwatch({
  label,
  color,
  selected,
  onSelect,
}: {
  label: string
  color?: string
  selected: boolean
  onSelect: () => void
}) {
  return (
    <ContextMenuItem
      onSelect={onSelect}
      role="menuitemradio"
      aria-checked={selected}
      title={label}
      aria-label={label}
      className={cn(
        'size-6 justify-center rounded-sm border border-slate-300 p-0',
        // Focus is drawn the same way and declared after, so while a swatch is
        // being aimed at the blue wins and the selected ring reappears on the
        // way out.
        selected && 'ring-2 ring-slate-900 ring-offset-1',
        'focus:ring-2 focus:ring-blue-500 focus:ring-offset-1'
      )}
      style={color ? { backgroundColor: color } : undefined}
    >
      {!color && <Ban className="size-3 text-slate-400" />}
    </ContextMenuItem>
  )
}
