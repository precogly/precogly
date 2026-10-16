/**
 * One countermeasure row of the selected threat (UX simplification 3.3):
 * the status dot with its word, the number and the name. Clicking the row
 * opens the countermeasure modal, where everything else is viewed and edited.
 */

import { GripVertical } from 'lucide-react'
import { cn } from '@/lib/utils'
import { COUNTERMEASURE_STATUS_CONFIG, type AnalysisCountermeasure, type CountermeasureStatus } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'

/** Assignee type for the combobox: individuals only. */
export type Assignee = { type: 'member'; userId: number; email: string; name: string | null }

/** A status dot with its word beside it, never the colour alone. */
export function CountermeasureStatusDot({ status, className }: { status: CountermeasureStatus; className?: string }) {
  const config = COUNTERMEASURE_STATUS_CONFIG[status]
  return (
    <span className={cn('inline-flex shrink-0 items-center gap-1 text-xs', className)} data-countermeasure-status={status}>
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: config.color }} />
      <span className="text-muted-foreground">{config.label}</span>
    </span>
  )
}

export interface CountermeasureCardProps {
  countermeasure: AnalysisCountermeasure
  dragHandleRef?: React.RefCallback<HTMLElement>
  /** Whether this row's modal is open. */
  isOpen: boolean
  onOpen: () => void
}

export function CountermeasureCard({ countermeasure, dragHandleRef, isOpen, onOpen }: CountermeasureCardProps) {
  const name = countermeasure.countermeasureName || countermeasure.countermeasureId
  return (
    <div
      className={cn(
        'group mb-1 flex items-center gap-2 rounded-md border px-2 py-1.5 transition-colors',
        isOpen ? 'border-slate-300 bg-slate-100' : 'hover:bg-slate-50'
      )}
      data-countermeasure-number={countermeasure.displayNumber}
    >
      {dragHandleRef && (
        <div
          ref={dragHandleRef}
          className="shrink-0 cursor-grab opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100"
        >
          <GripVertical className="h-4 w-4 text-muted-foreground" />
        </div>
      )}
      <button
        type="button"
        onClick={onOpen}
        className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left"
        aria-label={`Open ${countermeasure.displayNumber ?? ''} ${name}`.trim()}
        aria-expanded={isOpen}
      >
        <CountermeasureStatusDot status={countermeasure.status} className="w-[84px]" />
        <NumberBadge number={countermeasure.displayNumber} />
        <span className="truncate text-sm font-medium">{name}</span>
      </button>
    </div>
  )
}
