/**
 * The list of threats in the middle column. A row shows three things: the
 * number, the title and the state. Clicking a row selects the threat (the
 * countermeasures column follows it) and opens the threat modal, where
 * everything else is viewed and edited. Shared by the component view and the
 * "By use case" view, so a threat is the same row in both and every edit
 * applies to the one scenario.
 *
 * The open modal can be controlled by the caller (the page keeps it in the
 * URL as `?threat=T17`); without that the list keeps it itself.
 */

import { useMemo, useState, type ReactNode } from 'react'
import { ChevronDown, ChevronUp, GripVertical, Unlink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import { SortableList } from '@/components/shared/SortableList'
import { isActiveThreat, TRIAGE_STATUS_COLORS, TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import type { AnalysisThreat } from '../../types/threat-analysis'
import { deriveThreatStatus } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'
import { ThreatEditor } from './ThreatEditor'
import { ThreatStatusBadge } from './ThreatStatusBadge'
import { type AnalysisSelection } from './analysis-selection'

export { ThreatStatusBadge }

export interface ThreatListProps {
  /** Buttons shown under "No threats here yet." (the use case view's add and link). */
  emptyActions?: ReactNode
  threatModelId: string
  /** The threats of the selection, in any order. */
  threats: AnalysisThreat[]
  /** Whether anything is selected; the empty messages show only then. */
  hasSelection: boolean
  /** The tree selection, so the modal's targets list marks the one already shown. */
  selection?: AnalysisSelection | null
  selectedThreatId: string | null
  onSelectThreat: (threatId: string) => void
  /** The display number of the threat whose modal is open; omit to let the list keep it. */
  openThreatNumber?: string | null
  onOpenThreatChange?: (displayNumber: string | null) => void
  /** Makes the modal's other targets clickable. */
  onSelectTarget?: (selection: AnalysisSelection) => void
  onUpdateTriageStatus: (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  /** Called with the new order of the active threats; omit to keep the order fixed. */
  onReorder?: (reorderedThreats: AnalysisThreat[]) => void
  /** Makes a threat's "From abuse cases" names links. */
  onOpenAbuseCase?: (abuseCaseId: number) => void
  /** Adds an "Unlink" button to each row (the threat stays; only the link goes). */
  onUnlink?: (threat: AnalysisThreat) => void
  unlinkLabel?: string
  /** Called after the targets were saved. */
  onTargetsSaved?: (wholeSystem: boolean) => void
}

export function ThreatList({
  threatModelId,
  threats,
  hasSelection,
  selection = null,
  selectedThreatId,
  onSelectThreat,
  openThreatNumber: controlledOpenThreatNumber,
  onOpenThreatChange,
  onSelectTarget,
  onUpdateTriageStatus,
  onReorder,
  onOpenAbuseCase,
  onUnlink,
  unlinkLabel = 'Unlink',
  emptyActions,
  onTargetsSaved,
}: ThreatListProps) {
  const [showTriagedThreats, setShowTriagedThreats] = useState(false)
  const [localOpenThreatNumber, setLocalOpenThreatNumber] = useState<string | null>(null)

  const isControlled = onOpenThreatChange !== undefined
  const openThreatNumber = isControlled ? controlledOpenThreatNumber ?? null : localOpenThreatNumber
  const setOpenThreatNumber = (displayNumber: string | null) => {
    if (isControlled) onOpenThreatChange(displayNumber)
    else setLocalOpenThreatNumber(displayNumber)
  }

  const activeThreats = useMemo(
    () =>
      threats
        .filter((threat) => isActiveThreat(threat.triageStatus))
        .sort((left, right) => (left.displayOrder ?? 0) - (right.displayOrder ?? 0) || left.number - right.number),
    [threats]
  )
  const triagedThreats = threats.filter((threat) => !isActiveThreat(threat.triageStatus))
  const openThreat = openThreatNumber
    ? threats.find((threat) => threat.displayNumber === openThreatNumber) ?? null
    : null

  // A click selects the threat and opens its modal; a second click on the open row closes it.
  const handleRowClick = (threat: AnalysisThreat) => {
    if (openThreat?.id === threat.id) {
      setOpenThreatNumber(null)
      return
    }
    onSelectThreat(threat.id)
    setOpenThreatNumber(threat.displayNumber)
  }

  /** Number, title and a pill; the drag handle and the use case view's Unlink sit beside them. */
  const renderRow = (threat: AnalysisThreat, pill: ReactNode, options: { dragHandleRef?: React.RefCallback<HTMLElement>; struckThrough?: boolean; trailing?: ReactNode }) => {
    const isOpen = openThreat?.id === threat.id
    return (
      <div
        className={cn(
          'group flex items-center gap-1 rounded-md px-2 py-1.5 transition-colors',
          isOpen ? 'border border-slate-300 bg-slate-100' : 'border border-transparent hover:bg-slate-50'
        )}
        data-threat-number={threat.displayNumber}
        data-selected={threat.id === selectedThreatId ? 'true' : undefined}
      >
        {/* No handle where the order is not saved (the use case view and the triaged group). */}
        {options.dragHandleRef && (
          <div
            ref={options.dragHandleRef}
            className="shrink-0 cursor-grab opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100"
          >
            <GripVertical className="h-4 w-4 text-muted-foreground" />
          </div>
        )}
        <button
          type="button"
          onClick={() => handleRowClick(threat)}
          className="flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 text-left"
          aria-label={`Open ${threat.displayNumber} ${threat.threatName || 'Unnamed threat'}`}
          aria-expanded={isOpen}
        >
          <NumberBadge number={threat.displayNumber} />
          <span className={cn('truncate text-sm font-medium', options.struckThrough && 'text-muted-foreground line-through')}>
            {threat.threatName || 'Unnamed threat'}
          </span>
        </button>
        {pill}
        {onUnlink && (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100 touch:opacity-100"
            onClick={() => onUnlink(threat)}
            title={unlinkLabel}
            aria-label={`${unlinkLabel}: ${threat.displayNumber}`}
          >
            <Unlink className="h-3 w-3" />
          </Button>
        )}
        {options.trailing}
      </div>
    )
  }

  const renderActiveRow = (threat: AnalysisThreat, dragHandleRef?: React.RefCallback<HTMLElement>) =>
    renderRow(threat, <ThreatStatusBadge status={deriveThreatStatus(threat.countermeasures)} />, {
      dragHandleRef: onReorder ? dragHandleRef : undefined,
    })

  const renderTriagedRow = (threat: AnalysisThreat) => {
    const triageLabel = TRIAGE_STATUSES.find((entry) => entry.value === threat.triageStatus)?.label || threat.triageStatus
    return renderRow(
      threat,
      <Badge variant="outline" className={cn('shrink-0 text-[10px]', TRIAGE_STATUS_COLORS[threat.triageStatus])}>
        {triageLabel}
      </Badge>,
      {
        struckThrough: true,
        trailing: (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 shrink-0 text-xs text-blue-600 hover:bg-blue-50 hover:text-blue-700"
            onClick={() => onUpdateTriageStatus(threat.id, 'open')}
          >
            Reopen
          </Button>
        ),
      }
    )
  }

  return (
    <>
      <ScrollArea className="flex-1">
        <div className="space-y-1 p-2">
          {activeThreats.length > 0 &&
            (onReorder ? (
              <SortableList
                items={activeThreats}
                getItemId={(threat) => threat.id}
                onReorder={onReorder}
                renderItem={renderActiveRow}
              />
            ) : (
              // Where the order is not saved (the use case view) the rows are a plain list, not draggable.
              activeThreats.map((threat) => <div key={threat.id}>{renderActiveRow(threat)}</div>)
            ))}

          {hasSelection && activeThreats.length === 0 && triagedThreats.length === 0 && (
            <div className="py-8 text-center text-muted-foreground">
              <p className="text-sm">No threats here yet.</p>
              {emptyActions && <div className="mt-3 flex justify-center">{emptyActions}</div>}
            </div>
          )}

          {hasSelection && activeThreats.length === 0 && triagedThreats.length > 0 && (
            <div className="py-8 text-center text-muted-foreground">
              <p className="text-sm">All threats have been triaged.</p>
              <p className="mt-1 text-xs">Reopen from the section below if needed.</p>
            </div>
          )}

          {hasSelection && triagedThreats.length > 0 && (
            <div className="mt-4 border-t pt-3">
              <button
                className="flex w-full items-center justify-between px-2 py-1 text-sm text-muted-foreground hover:text-foreground"
                onClick={() => setShowTriagedThreats((open) => !open)}
                aria-expanded={showTriagedThreats}
              >
                <div className="flex items-center gap-2">
                  <span className="font-medium">Triaged threats</span>
                  <Badge variant="outline" className="bg-slate-100 text-xs">
                    {triagedThreats.length}
                  </Badge>
                </div>
                {showTriagedThreats ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {showTriagedThreats && (
                <div className="mt-2 space-y-1">
                  {triagedThreats.map((threat) => (
                    <div key={threat.id}>{renderTriagedRow(threat)}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </ScrollArea>

      <ThreatEditor
        threatModelId={threatModelId}
        threat={openThreat}
        onClose={() => setOpenThreatNumber(null)}
        onUpdateTriageStatus={onUpdateTriageStatus}
        selection={selection}
        onSelectTarget={onSelectTarget}
        onOpenAbuseCase={onOpenAbuseCase}
        onTargetsSaved={onTargetsSaved}
        onDeleted={() => setOpenThreatNumber(null)}
      />
    </>
  )
}
