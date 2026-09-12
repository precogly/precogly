import { useState } from 'react'
import { ChevronLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'
import { TABLE_DEFAULT_COLUMNS, TABLE_DEFAULT_ROWS } from '../../types'

/**
 * Size of the hover grid. Table size itself is unbounded, so this is the
 * largest table the grid can express, not the largest table there is: input
 * mode goes past it, and the grid then clamps its highlight to these bounds —
 * 17 rows shows as all 8 filled. Growing the grid to chase the input would make
 * it a thicket of unclickable squares.
 */
const GRID_COLUMNS = 8
const GRID_ROWS = 8

interface TableSize {
  columns: number
  rows: number
}

interface TableGridPickerProps {
  onPick: (size: TableSize) => void
}

/**
 * Size chooser shown when the Table palette entry is clicked.
 *
 * Two modes over one grid. In draw mode, hovering highlights a rectangle from
 * the top-left and a click inserts that size straight away. In input mode the
 * same grid becomes a preview of the typed numbers, and Create Table commits —
 * clicking the grid there sets the numbers rather than inserting, since the
 * whole point of the mode is to name a size the grid cannot reach.
 *
 * Free-text counts are safe here in a way they are not in the edit panel. The
 * table does not exist yet, so a half-typed "1" on the way to "12" has no cells
 * to discard; the value is read only when Create Table is pressed.
 */
export function TableGridPicker({ onPick }: TableGridPickerProps) {
  const [inputMode, setInputMode] = useState(false)
  const [hover, setHover] = useState<TableSize | null>(null)
  const [columnDraft, setColumnDraft] = useState(String(TABLE_DEFAULT_COLUMNS))
  const [rowDraft, setRowDraft] = useState(String(TABLE_DEFAULT_ROWS))

  const typed = {
    columns: Number(columnDraft),
    rows: Number(rowDraft),
  }
  const typedValid =
    Number.isFinite(typed.columns) &&
    Number.isFinite(typed.rows) &&
    typed.columns >= 1 &&
    typed.rows >= 1

  // In draw mode the grid follows the cursor; in input mode it previews what
  // has been typed, so the two modes never disagree about what will be made.
  const highlight = inputMode ? (typedValid ? typed : null) : hover

  const handleCellClick = (size: TableSize) => {
    if (inputMode) {
      setColumnDraft(String(size.columns))
      setRowDraft(String(size.rows))
    } else {
      onPick(size)
    }
  }

  return (
    <div className="w-52 space-y-2">
      {inputMode ? (
        <button
          type="button"
          onClick={() => setInputMode(false)}
          className="flex items-center gap-0.5 text-xs font-medium text-primary hover:underline"
        >
          <ChevronLeft className="h-3 w-3" />
          Back to draw grid mode
        </button>
      ) : (
        <div className="text-xs font-medium">
          {hover ? `${hover.columns} × ${hover.rows}` : 'Insert table'}
        </div>
      )}

      <div
        role="grid"
        aria-label="Table size"
        onMouseLeave={() => !inputMode && setHover(null)}
        className="grid gap-0.5"
        style={{ gridTemplateColumns: `repeat(${GRID_COLUMNS}, 1.25rem)` }}
      >
        {Array.from({ length: GRID_ROWS }, (_, rowIndex) =>
          Array.from({ length: GRID_COLUMNS }, (_, colIndex) => {
            const columns = colIndex + 1
            const rows = rowIndex + 1
            const highlighted =
              !!highlight &&
              columns <= Math.min(highlight.columns, GRID_COLUMNS) &&
              rows <= Math.min(highlight.rows, GRID_ROWS)

            return (
              <button
                key={`${rowIndex}-${colIndex}`}
                type="button"
                aria-label={`${columns} by ${rows}`}
                onMouseEnter={() => !inputMode && setHover({ columns, rows })}
                onFocus={() => !inputMode && setHover({ columns, rows })}
                onClick={() => handleCellClick({ columns, rows })}
                className={cn(
                  'h-5 w-5 rounded-[2px] border',
                  highlighted ? 'border-primary bg-primary/30' : 'border-border bg-muted/40'
                )}
              />
            )
          })
        )}
      </div>

      {inputMode ? (
        <div className="space-y-2 pt-1">
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="picker-rows" className="text-sm font-normal">
              Rows
            </Label>
            <Input
              id="picker-rows"
              type="number"
              min={1}
              value={rowDraft}
              onChange={(event) => setRowDraft(event.target.value)}
              className="h-7 w-16 px-2 text-sm"
              autoFocus
            />
          </div>
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="picker-columns" className="text-sm font-normal">
              Columns
            </Label>
            <Input
              id="picker-columns"
              type="number"
              min={1}
              value={columnDraft}
              onChange={(event) => setColumnDraft(event.target.value)}
              className="h-7 w-16 px-2 text-sm"
            />
          </div>
          <Button
            className="w-full"
            size="sm"
            disabled={!typedValid}
            onClick={() => onPick(typed)}
          >
            Create Table
          </Button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setInputMode(true)}
          className="text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          Switch to input
        </button>
      )}
    </div>
  )
}
