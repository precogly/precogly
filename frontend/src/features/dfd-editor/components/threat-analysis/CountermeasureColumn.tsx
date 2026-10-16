/**
 * The right column of the threat analysis screen: the countermeasures of the
 * selected scenario, one row each (status dot with its word, number, name).
 * A row opens the countermeasure modal. Shared by the component view and the
 * "By use case" view.
 *
 * The open modal can be controlled by the caller (the page keeps it in the
 * URL as `?countermeasure=C5`); without that the column keeps it itself.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { AlarmClock, Loader2, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { ResizablePanel } from '@/components/ui/resizable'
import { SortableList } from '@/components/shared/SortableList'
import { useDeleteCountermeasure, useUnlinkCountermeasure } from '@/features/threat-models/api/threats'
import type {
  AnalysisCountermeasure,
  AnalysisThreat,
  ComplianceStandardMapping,
  CountermeasureStatus,
} from '../../types/threat-analysis'
import { EditComplianceMappingsDialog } from './EditComplianceMappingsDialog'
import { CountermeasureCard, type Assignee } from './CountermeasureCard'
import { CountermeasureDetailDialog } from './CountermeasureDetailDialog'
import { UnattachedControlsBlock } from './UnattachedControlsBlock'
import { NumberBadge } from './NumberBadge'
import { StepNumber } from './StepNumber'
import { formatTargetList, isCountermeasureOverdue } from './countermeasure-utils'

export interface CountermeasureColumnProps {
  threatModelId: string
  /** Every scenario shown, for the controls that are linked to no threat. */
  threats: AnalysisThreat[]
  selectedThreat: AnalysisThreat | null
  onSelectThreatByBackendId: (backendThreatId: number) => void
  /** Select another threat and open its modal (the countermeasure modal's "Mitigates" links). */
  onOpenThreatByBackendId?: (backendThreatId: number) => void
  /** The display number of the countermeasure whose modal is open; omit to let the column keep it. */
  openCountermeasureNumber?: string | null
  onOpenCountermeasureChange?: (displayNumber: string | null) => void
  onCountermeasureStatusChange: (
    threatUiId: string,
    countermeasureId: string,
    status: CountermeasureStatus,
    notes?: string
  ) => void
  onAssignOwner: (threatUiId: string, countermeasureId: string, assignee: Assignee, newStatus?: CountermeasureStatus) => void
  onAddCustomCountermeasure: () => void
  onCountermeasurePriorityChange: (threatUiId: string, countermeasureId: string, priority: AnalysisCountermeasure['priority']) => void
  onCountermeasureDueDateChange: (threatUiId: string, countermeasureId: string, dueDate: string | null) => void
  onCountermeasureExternalTicketChange: (threatUiId: string, countermeasureId: string, externalTicketUrl: string) => void
  onReorderCountermeasures?: (threatUiId: string, reorderedCountermeasures: AnalysisCountermeasure[]) => void
  isSecurityTeam?: boolean
  /** Shown before the title in the "By Use Case" view, where the columns are numbered steps. */
  stepNumber?: number
}

export function CountermeasureColumn({
  threatModelId,
  threats,
  selectedThreat,
  onSelectThreatByBackendId,
  onOpenThreatByBackendId,
  openCountermeasureNumber: controlledOpenCountermeasureNumber,
  onOpenCountermeasureChange,
  onCountermeasureStatusChange,
  onAssignOwner,
  onAddCustomCountermeasure,
  onCountermeasurePriorityChange,
  onCountermeasureDueDateChange,
  onCountermeasureExternalTicketChange,
  onReorderCountermeasures,
  isSecurityTeam,
  stepNumber,
}: CountermeasureColumnProps) {
  const [editingComplianceFor, setEditingComplianceFor] = useState<{
    backendId: number
    name: string
    mappings: ComplianceStandardMapping[]
  } | null>(null)
  const [deleteCountermeasureConfirmFor, setDeleteCountermeasureConfirmFor] = useState<{
    name: string
    backendId: number
    isShared?: boolean
    threatId: number
  } | null>(null)

  const [localOpenCountermeasureNumber, setLocalOpenCountermeasureNumber] = useState<string | null>(null)
  const isControlled = onOpenCountermeasureChange !== undefined
  const openCountermeasureNumber = isControlled ? controlledOpenCountermeasureNumber ?? null : localOpenCountermeasureNumber
  const setOpenCountermeasureNumber = (displayNumber: string | null) => {
    if (isControlled) onOpenCountermeasureChange(displayNumber)
    else setLocalOpenCountermeasureNumber(displayNumber)
  }

  const deleteCountermeasureMutation = useDeleteCountermeasure()
  const unlinkCountermeasureMutation = useUnlinkCountermeasure()

  const sortedCountermeasures = useMemo(
    () =>
      [...(selectedThreat?.countermeasures ?? [])].sort((left, right) => (left.displayOrder ?? 0) - (right.displayOrder ?? 0)),
    [selectedThreat?.countermeasures]
  )
  const openCountermeasure = openCountermeasureNumber
    ? sortedCountermeasures.find((countermeasure) => countermeasure.displayNumber === openCountermeasureNumber) ?? null
    : null
  // Overdue: past the due date and not yet in effect (the backend's days_overdue rule).
  // The chip filters the list to them; the filter belongs to the threat it was set on.
  const overdueCountermeasures = useMemo(
    () => sortedCountermeasures.filter((countermeasure) => isCountermeasureOverdue(countermeasure)),
    [sortedCountermeasures]
  )
  const [overdueFilterThreatId, setOverdueFilterThreatId] = useState<string | null>(null)
  const showOnlyOverdue =
    selectedThreat !== null && overdueFilterThreatId === selectedThreat.id && overdueCountermeasures.length > 0
  const totalCountermeasures = selectedThreat?.countermeasures.length ?? 0
  const resolvedCountermeasures = selectedThreat?.countermeasures.filter((countermeasure) => countermeasure.status !== 'gap').length ?? 0

  const handleConfirmDeleteCountermeasure = () => {
    if (!deleteCountermeasureConfirmFor) return
    const { isShared, backendId, threatId } = deleteCountermeasureConfirmFor
    const onSuccess = () => {
      toast.success(isShared ? 'Countermeasure unlinked' : 'Countermeasure removed')
      setDeleteCountermeasureConfirmFor(null)
      setOpenCountermeasureNumber(null)
    }
    const onError = () => toast.error(isShared ? 'Could not unlink the countermeasure' : 'Could not remove the countermeasure')
    unlinkCountermeasureMutation.mutate({ countermeasureId: backendId, threatId }, { onSuccess, onError })
  }

  return (
        <ResizablePanel defaultSize="42%" minSize="20%">
          <div className="flex h-full flex-col">
            <div className="flex items-center justify-between border-b px-4 py-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 font-medium">
                  {stepNumber !== undefined && <StepNumber step={stepNumber} />}
                  Countermeasures
                  {selectedThreat && (
                    <span className="text-xs font-normal text-muted-foreground" data-testid="countermeasure-count">
                      ({totalCountermeasures})
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  {selectedThreat ? (
                    <>
                      <NumberBadge number={selectedThreat.displayNumber} />
                      <span className="truncate">{selectedThreat.threatName}</span>
                      <span className="shrink-0">on {formatTargetList(selectedThreat.targets, 2)}</span>
                    </>
                  ) : (
                    'Select a threat'
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {selectedThreat && overdueCountermeasures.length > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    className={cn(
                      'h-7 gap-1 border-red-300 text-xs text-red-700 hover:bg-red-50 hover:text-red-800',
                      showOnlyOverdue && 'bg-red-50'
                    )}
                    onClick={() => setOverdueFilterThreatId(showOnlyOverdue ? null : selectedThreat.id)}
                    aria-pressed={showOnlyOverdue}
                    title={showOnlyOverdue ? 'Show all countermeasures' : 'Show only overdue countermeasures'}
                    data-testid="overdue-filter"
                  >
                    <AlarmClock className="h-3 w-3" />
                    {overdueCountermeasures.length} overdue
                  </Button>
                )}
                {selectedThreat && (
                  <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={onAddCustomCountermeasure}>
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                )}
              </div>
            </div>

            <ScrollArea className="flex-1">
              <div className="space-y-3 p-3">
                {showOnlyOverdue && (
                  // A subset is not reordered, so the filtered rows are a plain list.
                  <div>
                    {overdueCountermeasures.map((countermeasure) => (
                      <CountermeasureCard
                        key={countermeasure.id}
                        countermeasure={countermeasure}
                        isOpen={openCountermeasure?.id === countermeasure.id}
                        onOpen={() =>
                          setOpenCountermeasureNumber(
                            openCountermeasure?.id === countermeasure.id ? null : countermeasure.displayNumber ?? null
                          )
                        }
                      />
                    ))}
                  </div>
                )}
                {selectedThreat && !showOnlyOverdue && sortedCountermeasures.length > 0 && (
                  <SortableList
                    items={sortedCountermeasures}
                    getItemId={(countermeasure) => countermeasure.id}
                    onReorder={(reordered) => {
                      if (onReorderCountermeasures) onReorderCountermeasures(selectedThreat.id, reordered)
                    }}
                    renderItem={(countermeasure, dragHandleRef) => (
                      <CountermeasureCard
                        countermeasure={countermeasure}
                        dragHandleRef={dragHandleRef}
                        isOpen={openCountermeasure?.id === countermeasure.id}
                        onOpen={() =>
                          setOpenCountermeasureNumber(
                            openCountermeasure?.id === countermeasure.id ? null : countermeasure.displayNumber ?? null
                          )
                        }
                      />
                    )}
                  />
                )}
                {selectedThreat && sortedCountermeasures.length === 0 && (
                  <p className="py-6 text-center text-sm text-muted-foreground">No countermeasures linked to this threat.</p>
                )}
                {!selectedThreat && <UnattachedControlsBlock threatModelId={threatModelId} threats={threats} />}
              </div>
            </ScrollArea>

            {selectedThreat && (
              <div className="flex justify-between border-t px-4 py-2 text-xs text-muted-foreground">
                <span>{totalCountermeasures} countermeasures</span>
                <span>{resolvedCountermeasures} resolved</span>
              </div>
            )}

      {selectedThreat && (
        <CountermeasureDetailDialog
          threatModelId={threatModelId}
          threat={selectedThreat}
          countermeasure={openCountermeasure}
          onClose={() => setOpenCountermeasureNumber(null)}
          isSecurityTeam={isSecurityTeam}
          onStatusChange={(countermeasureId, status, notes) =>
            onCountermeasureStatusChange(selectedThreat.id, countermeasureId, status, notes)
          }
          onAssignOwner={(countermeasureId, assignee, newStatus) =>
            onAssignOwner(selectedThreat.id, countermeasureId, assignee, newStatus)
          }
          onPriorityChange={(countermeasureId, priority) =>
            onCountermeasurePriorityChange(selectedThreat.id, countermeasureId, priority)
          }
          onDueDateChange={(countermeasureId, dueDate) =>
            onCountermeasureDueDateChange(selectedThreat.id, countermeasureId, dueDate)
          }
          onExternalTicketChange={(countermeasureId, url) =>
            onCountermeasureExternalTicketChange(selectedThreat.id, countermeasureId, url)
          }
          onRequestDelete={(target) => {
            if (target.backendCountermeasureId === undefined) return
            setDeleteCountermeasureConfirmFor({
              name: target.countermeasureName || target.countermeasureId,
              backendId: target.backendCountermeasureId,
              isShared: target.isShared,
              threatId: selectedThreat.backendThreatId,
            })
          }}
          onEditCompliance={(target) => {
            if (target.backendCountermeasureId === undefined) return
            setEditingComplianceFor({
              backendId: target.backendCountermeasureId,
              name: target.countermeasureName || target.countermeasureId,
              mappings: target.standardMappings || [],
            })
          }}
          onOpenThreat={(backendThreatId) => {
            setOpenCountermeasureNumber(null)
            if (onOpenThreatByBackendId) onOpenThreatByBackendId(backendThreatId)
            else onSelectThreatByBackendId(backendThreatId)
          }}
        />
      )}

      {editingComplianceFor && (
        <EditComplianceMappingsDialog
          open
          onOpenChange={(open) => {
            if (!open) setEditingComplianceFor(null)
          }}
          countermeasureId={editingComplianceFor.backendId}
          countermeasureName={editingComplianceFor.name}
          libraryMappings={editingComplianceFor.mappings}
        />
      )}

      <AlertDialog
        open={!!deleteCountermeasureConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteCountermeasureConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {deleteCountermeasureConfirmFor?.isShared ? 'Remove countermeasure from this threat?' : 'Remove countermeasure?'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleteCountermeasureConfirmFor?.isShared
                ? `"${deleteCountermeasureConfirmFor.name}" stays linked to the other threats it mitigates.`
                : `"${deleteCountermeasureConfirmFor?.name}" loses its link to this threat. An untouched generated control is deleted; anything edited is kept and listed as not linked to any threat.`}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={unlinkCountermeasureMutation.isPending || deleteCountermeasureMutation.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDeleteCountermeasure()
              }}
              disabled={unlinkCountermeasureMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {unlinkCountermeasureMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Removing
                </>
              ) : (
                'Remove'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
          </div>
        </ResizablePanel>
  )
}
