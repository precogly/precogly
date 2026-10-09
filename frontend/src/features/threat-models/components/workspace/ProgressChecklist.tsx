import { useState } from 'react'
import { AlertTriangle, CheckCircle2, Circle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import type {
  CompletionStatus,
  CoverageItem,
  ProgressChecklistItem,
  QualitySignal,
  SystemDefinitionItem,
} from '@/features/dfd-editor/types/threat-analysis'

interface CompletionStatusCardProps {
  completionStatus?: CompletionStatus
  progressChecklist?: ProgressChecklistItem[]
}

export function CompletionStatusCard({ completionStatus, progressChecklist }: CompletionStatusCardProps) {
  const [crossCheckOpen, setCrossCheckOpen] = useState(false)

  // Fall back to legacy rendering if no completionStatus available
  if (!completionStatus) {
    return <LegacyChecklist items={progressChecklist || []} />
  }

  return (
    <div className="space-y-4">
      {/* Two-column grid: System Definition + Coverage */}
      <div className="grid grid-cols-2 gap-x-8">
        {/* Left: System Definition */}
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            System Definition
          </h4>
          <div className="space-y-2">
            {completionStatus.systemDefinition.map((item) => (
              <SystemDefinitionRow key={item.id} item={item} />
            ))}
          </div>
        </div>

        {/* Right: Coverage */}
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Coverage
          </h4>
          <div className="space-y-3">
            {completionStatus.coverage.map((item) => (
              <CoverageRow key={item.id} item={item} />
            ))}
          </div>
        </div>
      </div>

      {/* Pack Cross-Check Summary */}
      {completionStatus.qualitySignals.length > 0 && (
        <>
          <PackCrossCheckSummary
            signals={completionStatus.qualitySignals}
            onViewDetails={() => setCrossCheckOpen(true)}
          />
          <PackCrossCheckModal
            open={crossCheckOpen}
            onOpenChange={setCrossCheckOpen}
            signals={completionStatus.qualitySignals}
          />
        </>
      )}
    </div>
  )
}

function SystemDefinitionRow({ item }: { item: SystemDefinitionItem }) {
  return (
    <div className="flex items-center gap-2">
      {item.checked ? (
        <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
      ) : (
        <Circle className="h-4 w-4 text-muted-foreground shrink-0" />
      )}
      <span className={cn('text-sm flex-1', !item.checked && 'text-muted-foreground')}>
        {item.label}
      </span>
      <Badge variant="secondary" className="text-xs">
        {item.countLabel}
      </Badge>
    </div>
  )
}

function CoverageRow({ item }: { item: CoverageItem }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{item.label}</span>
        <span className="text-xs font-medium tabular-nums">
          {item.numerator}/{item.denominator}
        </span>
      </div>
      <Progress value={item.percentage} />
    </div>
  )
}

function PackCrossCheckSummary({
  signals,
  onViewDetails,
}: {
  signals: QualitySignal[]
  onViewDetails: () => void
}) {
  const flaggedCount = signals.reduce(
    (count, s) => count + (s.status === 'warning' ? s.flaggedItems.length : 0),
    0,
  )

  return (
    <div className="border-t pt-3 flex items-center justify-between">
      <div className="flex items-center gap-2">
        {flaggedCount === 0 ? (
          <>
            <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
            <span className="text-sm text-green-700">All entries match installed packs</span>
          </>
        ) : (
          <>
            <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
            <span className="text-sm text-amber-700">
              {flaggedCount} {flaggedCount === 1 ? 'item' : 'items'} flagged
            </span>
          </>
        )}
      </div>
      <Button variant="ghost" size="sm" onClick={onViewDetails}>
        View Details
      </Button>
    </div>
  )
}

function PackCrossCheckModal({
  open,
  onOpenChange,
  signals,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  signals: QualitySignal[]
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Pack Cross-Check</DialogTitle>
          <DialogDescription>
            Entries cross-checked against installed library packs
          </DialogDescription>
        </DialogHeader>
        <ScrollArea className="max-h-[60vh]">
          <div className="space-y-3">
            {signals.map((signal) => (
              <QualitySignalRow key={signal.id} signal={signal} />
            ))}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  )
}

function QualitySignalRow({ signal }: { signal: QualitySignal }) {
  const isOk = signal.status === 'ok'

  return (
    <div>
      <div className="flex items-center gap-2">
        {isOk ? (
          <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
        ) : (
          <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
        )}
        <span className={cn('text-sm', isOk ? 'text-green-700' : 'text-amber-700')}>
          {isOk ? signal.okLabel : signal.warningLabel}
        </span>
      </div>
      {!isOk && signal.flaggedItems.length > 0 && (
        <ul className="ml-6 mt-1 space-y-0.5">
          {signal.flaggedItems.slice(0, 5).map((flaggedItem) => (
            <li key={flaggedItem.id} className="text-xs text-muted-foreground">
              <span className="font-medium">{flaggedItem.name}</span>
              {flaggedItem.detail && <span>: {flaggedItem.detail}</span>}
            </li>
          ))}
          {signal.flaggedItems.length > 5 && (
            <li className="text-xs text-muted-foreground italic">
              +{signal.flaggedItems.length - 5} more
            </li>
          )}
        </ul>
      )}
    </div>
  )
}

/** Legacy fallback rendering using the old ProgressChecklistItem format */
function LegacyChecklist({ items }: { items: ProgressChecklistItem[] }) {
  const midpoint = Math.ceil(items.length / 2)
  const leftColumn = items.slice(0, midpoint)
  const rightColumn = items.slice(midpoint)

  return (
    <div className="grid grid-cols-2 gap-x-8 gap-y-2">
      <div className="space-y-2">
        {leftColumn.map((item) => (
          <div key={item.id} className="flex items-center gap-2">
            {item.checked ? (
              <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
            ) : (
              <Circle className="h-4 w-4 text-muted-foreground shrink-0" />
            )}
            <span className={cn('text-sm', !item.checked && 'text-muted-foreground')}>
              {item.label}
            </span>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        {rightColumn.map((item) => (
          <div key={item.id} className="flex items-center gap-2">
            {item.checked ? (
              <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
            ) : (
              <Circle className="h-4 w-4 text-muted-foreground shrink-0" />
            )}
            <span className={cn('text-sm', !item.checked && 'text-muted-foreground')}>
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

