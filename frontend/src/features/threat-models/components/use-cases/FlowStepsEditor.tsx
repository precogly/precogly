/** Ordered steps: add, edit, remove, move up and down. An imported `actor` shows read-only and is kept. */

import { ArrowDown, ArrowUp, Plus, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { FlowStep } from '@/features/threat-models/types/core'
import { placeholderFor } from './use-case-examples'

interface FlowStepsEditorProps {
  label: string
  steps: FlowStep[]
  onChange: (steps: FlowStep[]) => void
  placeholder?: string
  /** Example per step, by position; later steps fall back to `placeholder`. */
  placeholders?: string[]
  disabled?: boolean
}

export function FlowStepsEditor({
  label,
  steps: savedSteps,
  onChange,
  placeholder = 'What happens next',
  placeholders,
  disabled,
}: FlowStepsEditorProps) {
  // An empty list shows one blank row, so its example is visible before
  // anything is added; blank rows are never saved.
  const showsBlankRow = savedSteps.length === 0
  const steps: FlowStep[] = showsBlankRow ? [{ description: '' }] : savedSteps
  const move = (index: number, offset: number) => {
    const target = index + offset
    if (target < 0 || target >= steps.length) return
    const next = [...steps]
    const [moved] = next.splice(index, 1)
    next.splice(target, 0, moved)
    onChange(next)
  }

  return (
    <div className="space-y-1.5" data-testid="flow-steps-editor">
      <div className="text-sm font-medium">{label}</div>
      {steps.map((step, index) => (
        <div key={index} className="flex items-center gap-1.5">
          <span className="w-5 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{index + 1}</span>
          {step.actor && (
            <Badge variant="outline" className="shrink-0 text-[10px]" title="Actor from the imported file">
              {step.actor}
            </Badge>
          )}
          <Input
            value={step.description}
            onChange={(event) =>
              onChange(steps.map((current, stepIndex) => (stepIndex === index ? { ...current, description: event.target.value } : current)))
            }
            placeholder={placeholderFor(placeholders, index, placeholder)}
            aria-label={`${label} step ${index + 1}`}
            disabled={disabled}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0"
            onClick={() => move(index, -1)}
            disabled={disabled || index === 0}
            aria-label={`Move step ${index + 1} up`}
          >
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0"
            onClick={() => move(index, 1)}
            disabled={disabled || index === steps.length - 1}
            aria-label={`Move step ${index + 1} down`}
          >
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0"
            onClick={() => onChange(steps.filter((_, stepIndex) => stepIndex !== index))}
            disabled={disabled || showsBlankRow}
            aria-label={`Remove step ${index + 1}`}
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
        onClick={() => onChange([...steps, { description: '' }])}
        disabled={disabled}
      >
        <Plus className="h-3 w-3" />
        Add step
      </Button>
    </div>
  )
}
