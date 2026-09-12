import { Minus, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  setTableColumnCount,
  setTableRowCount,
  type DiagramNode,
  type TableNodeData,
} from '../../types'

interface TableSizeFieldsProps {
  data: TableNodeData
  updateNodeData: (updates: Partial<DiagramNode['data']>) => void
}

interface CountStepperProps {
  label: string
  value: number
  onChange: (next: number) => void
}

/**
 * Stepper rather than a number field.
 *
 * A number field has to commit on blur or Enter, because committing per
 * keystroke passes through every prefix of what is typed: going from 3 columns
 * to 12 would commit `1` first and truncate nine columns of content before the
 * `2` arrived. Committing on blur instead means the canvas shows nothing until
 * focus leaves the field, so the change appears to need a second click
 * elsewhere to take effect. A stepper has neither problem — every press is one
 * complete, immediately applied change.
 */
function CountStepper({ label, value, onChange }: CountStepperProps) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 shrink-0"
          disabled={value <= 1}
          onClick={() => onChange(value - 1)}
          aria-label={`Remove ${label.toLowerCase().replace(/s$/, '')}`}
        >
          <Minus className="h-3 w-3" />
        </Button>
        <span className="min-w-8 text-center text-sm tabular-nums" aria-live="polite">
          {value}
        </span>
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 shrink-0"
          onClick={() => onChange(value + 1)}
          aria-label={`Add ${label.toLowerCase().replace(/s$/, '')}`}
        >
          <Plus className="h-3 w-3" />
        </Button>
      </div>
    </div>
  )
}

/** Column and row counts for a table node, shared by the signed-in and guest edit panels. */
export function TableSizeFields({ data, updateNodeData }: TableSizeFieldsProps) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <CountStepper
          label="Columns"
          value={data.columnWidths.length}
          onChange={(next) => updateNodeData(setTableColumnCount(data, next))}
        />
        <CountStepper
          label="Rows"
          value={data.rows.length}
          onChange={(next) => updateNodeData(setTableRowCount(data, next))}
        />
      </div>

      <p className="text-xs text-muted-foreground">
        Removing a column or row discards its cells. Undo restores them.
      </p>

      <label className="flex items-center gap-2 text-sm">
        <Checkbox
          checked={data.headerRow}
          onCheckedChange={(checked) => updateNodeData({ headerRow: checked === true })}
        />
        Header row
      </label>
    </div>
  )
}
