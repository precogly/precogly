/** Add, edit and remove text rows (preconditions, postconditions, detection opportunities). */

import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { placeholderFor } from './use-case-examples'

interface StringListEditorProps {
  label: string
  rows: string[]
  onChange: (rows: string[]) => void
  addLabel?: string
  placeholder?: string
  /** Example per row, by position; later rows fall back to `placeholder`. */
  placeholders?: string[]
  disabled?: boolean
}

export function StringListEditor({
  label,
  rows: savedRows,
  onChange,
  addLabel = 'Add',
  placeholder,
  placeholders,
  disabled,
}: StringListEditorProps) {
  // An empty list shows one blank row, so its example is visible before
  // anything is added; blank rows are never saved.
  const showsBlankRow = savedRows.length === 0
  const rows = showsBlankRow ? [''] : savedRows
  return (
    <div className="space-y-1.5" data-testid="string-list-editor">
      <div className="text-sm font-medium">{label}</div>
      {rows.map((row, index) => (
        <div key={index} className="flex items-center gap-1.5">
          <Input
            value={row}
            onChange={(event) => onChange(rows.map((current, rowIndex) => (rowIndex === index ? event.target.value : current)))}
            placeholder={placeholderFor(placeholders, index, placeholder)}
            aria-label={`${label} ${index + 1}`}
            disabled={disabled}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0"
            onClick={() => onChange(rows.filter((_, rowIndex) => rowIndex !== index))}
            aria-label={`Remove ${label} ${index + 1}`}
            disabled={disabled || showsBlankRow}
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 gap-1 px-2 text-xs"
        onClick={() => onChange([...rows, ''])}
        disabled={disabled}
      >
        <Plus className="h-3 w-3" />
        {addLabel}
      </Button>
    </div>
  )
}
