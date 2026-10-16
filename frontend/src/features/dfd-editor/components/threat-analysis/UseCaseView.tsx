/**
 * The "By Use Case" threat analysis view: four numbered columns that follow
 * the chain use case, abuse case, threat, countermeasure. Picking a use case
 * lists its abuse cases; picking an abuse case lists its threats; picking a
 * threat lists its countermeasures. An abuse case linked to several use cases
 * shows under each with a "shared" mark; abuse cases with no use case sit in
 * a "Not linked to a use case" group. The threat list and the countermeasure
 * column are the ones the component view uses, and threats come from the
 * same analysis payload, so a threat is one row in both views.
 */

import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { Link2, Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
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
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'
import {
  useAbuseCases,
  useDeleteAbuseCase,
  useUnlinkAbuseCaseThreat,
  useUseCases,
} from '@/features/threat-models/api/threat-models'
import { AbuseCaseDialog } from '@/features/threat-models/components/use-cases/AbuseCaseDialog'
import { UseCaseDialog } from '@/features/threat-models/components/use-cases/UseCaseDialog'
import { USE_CASE_GAP_LABELS, errorMessages } from '@/features/threat-models/components/use-cases/use-case-utils'
import type { AbuseCase, UnlinkedRealizes } from '@/features/threat-models/types/core'
import type { TriageStatus } from '@/types/triage'
import { isActiveThreat } from '@/types/triage'
import type { AnalysisCountermeasure, AnalysisThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { AddThreatDialog } from './AddThreatDialog'
import { LinkThreatDialog } from './LinkThreatDialog'
import { CountermeasureColumn } from './CountermeasureColumn'
import { ThreatList } from './ThreatList'
import type { Assignee } from './CountermeasureCard'
import { StepNumber } from './StepNumber'
import {
  abuseCaseHasNoThreat,
  abuseCasesForColumnEntry,
  buildAddThreatPreset,
  buildUseCaseTree,
  threatsForUseCaseSelection,
  columnEntryForSelection,
  type UseCaseViewSelection,
} from './use-case-view-utils'

export interface UseCaseViewProps {
  threatModelId: string
  /** The scenarios shown (the page may filter them by diagram). */
  threats: AnalysisThreat[]
  /** All threats of the model, for "Link existing"; not filtered by diagram. */
  allThreats: AnalysisThreat[]
  selection: UseCaseViewSelection | null
  onSelectionChange: (selection: UseCaseViewSelection | null) => void
  selectedThreatId: string | null
  selectedThreat: AnalysisThreat | null
  onSelectThreat: (threatId: string) => void
  /** The display numbers of the open threat and countermeasure modals (the page keeps them in the URL). */
  openThreatNumber?: string | null
  onOpenThreatChange?: (displayNumber: string | null) => void
  openCountermeasureNumber?: string | null
  onOpenCountermeasureChange?: (displayNumber: string | null) => void
  /** Switch to another abuse case (from a threat's "From abuse cases" links). */
  onOpenAbuseCase?: (abuseCaseId: number) => void
  onCountermeasureStatusChange: (
    threatUiId: string,
    countermeasureId: string,
    status: CountermeasureStatus,
    notes?: string
  ) => void
  onAssignOwner: (threatUiId: string, countermeasureId: string, assignee: Assignee, newStatus?: CountermeasureStatus) => void
  onUpdateTriageStatus: (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  onAddCustomCountermeasure: () => void
  onCountermeasurePriorityChange: (threatUiId: string, countermeasureId: string, priority: AnalysisCountermeasure['priority']) => void
  onCountermeasureDueDateChange: (threatUiId: string, countermeasureId: string, dueDate: string | null) => void
  onCountermeasureExternalTicketChange: (threatUiId: string, countermeasureId: string, externalTicketUrl: string) => void
  onReorderCountermeasures?: (threatUiId: string, reorderedCountermeasures: AnalysisCountermeasure[]) => void
  isSecurityTeam?: boolean
}

const GAP_BADGE_CLASS = 'shrink-0 border-amber-300 bg-amber-50 px-1 py-0 text-[10px] font-normal text-amber-800'

/** A column header: step number, title, actions on the right, and a muted line under it. */
function ColumnHeader({
  step,
  title,
  actions,
  children,
}: {
  step: number
  title: string
  actions?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="border-b px-3 py-2" data-testid={`use-case-view-step-${step}`}>
      <div className="flex min-h-7 items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 font-medium">
          <StepNumber step={step} />
          {title}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
      </div>
      {children && <div className="text-xs text-muted-foreground">{children}</div>}
    </div>
  )
}

/** A selectable row of the first two columns. */
function ColumnRow({
  isSelected,
  onSelect,
  testKey,
  children,
}: {
  isSelected: boolean
  onSelect: () => void
  testKey: string
  children: ReactNode
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      data-tree-key={testKey}
      aria-pressed={isSelected}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onSelect()
        }
      }}
      className={cn(
        'group w-full cursor-pointer rounded-md border p-1.5 text-left transition-colors',
        isSelected ? 'border-slate-300 bg-slate-100' : 'border-transparent hover:bg-slate-50'
      )}
    >
      {children}
    </div>
  )
}

export function UseCaseView({
  threatModelId,
  threats,
  allThreats,
  selection,
  onSelectionChange,
  selectedThreatId,
  selectedThreat,
  onSelectThreat,
  openThreatNumber,
  onOpenThreatChange,
  openCountermeasureNumber,
  onOpenCountermeasureChange,
  onOpenAbuseCase,
  onCountermeasureStatusChange,
  onAssignOwner,
  onUpdateTriageStatus,
  onAddCustomCountermeasure,
  onCountermeasurePriorityChange,
  onCountermeasureDueDateChange,
  onCountermeasureExternalTicketChange,
  onReorderCountermeasures,
  isSecurityTeam,
}: UseCaseViewProps) {
  const { data: useCases = [] } = useUseCases(threatModelId)
  const { data: abuseCases = [] } = useAbuseCases(threatModelId)
  const unlinkThreat = useUnlinkAbuseCaseThreat(threatModelId)
  const deleteAbuseCase = useDeleteAbuseCase(threatModelId)

  // The abuse case dialog: create under a use case, or edit one. The target is kept
  // while the dialog closes, so its title and form do not change during the close animation.
  const [abuseCaseDialog, setAbuseCaseDialog] = useState<
    { mode: 'create'; useCaseId?: number } | { mode: 'edit'; abuseCase: AbuseCase }
  >({ mode: 'create' })
  const [abuseCaseDialogOpen, setAbuseCaseDialogOpen] = useState(false)
  const openAbuseCaseDialog = (target: { mode: 'create'; useCaseId?: number } | { mode: 'edit'; abuseCase: AbuseCase }) => {
    setAbuseCaseDialog(target)
    setAbuseCaseDialogOpen(true)
  }
  const [deleteAbuseCaseFor, setDeleteAbuseCaseFor] = useState<AbuseCase | null>(null)
  const [useCaseDialogOpen, setUseCaseDialogOpen] = useState(false)
  const [addThreatFor, setAddThreatFor] = useState<AbuseCase | null>(null)
  // Kept while the link dialog closes, like the abuse case dialog target.
  const [linkThreatFor, setLinkThreatFor] = useState<AbuseCase | null>(null)
  const [linkThreatOpen, setLinkThreatOpen] = useState(false)
  const openLinkThreatDialog = (abuseCase: AbuseCase) => {
    setLinkThreatFor(abuseCase)
    setLinkThreatOpen(true)
  }

  const tree = useMemo(() => buildUseCaseTree(useCases, abuseCases), [useCases, abuseCases])

  const selectedAbuseCase =
    selection?.kind === 'abuseCase' ? abuseCases.find((abuseCase) => abuseCase.id === selection.abuseCaseId) ?? null : null

  // Column 1's highlighted entry, and the abuse cases column 2 lists for it.
  const columnEntry = useMemo(() => columnEntryForSelection(selection, abuseCases), [selection, abuseCases])
  const columnUseCase =
    columnEntry?.kind === 'useCase' ? useCases.find((useCase) => useCase.id === columnEntry.useCaseId) ?? null : null
  const columnAbuseCases = useMemo(() => abuseCasesForColumnEntry(columnEntry, tree), [columnEntry, tree])

  // Column 3 lists threats only for an abuse case: one step at a time.
  const threatsOfSelection = useMemo(
    () => (selectedAbuseCase ? threatsForUseCaseSelection(selection, abuseCases, threats) : []),
    [selectedAbuseCase, selection, abuseCases, threats]
  )
  const activeCount = threatsOfSelection.filter((threat) => isActiveThreat(threat.triageStatus)).length
  const selectionLabel = selectedAbuseCase ? `${selectedAbuseCase.name} (abuse case)` : 'Select an abuse case'

  const addThreatPreset = useMemo(
    () => (addThreatFor ? buildAddThreatPreset(addThreatFor, useCases) : null),
    [addThreatFor, useCases]
  )

  const selectThreatByBackendId = useCallback(
    (backendThreatId: number) => {
      const threat = threats.find((candidate) => candidate.backendThreatId === backendThreatId)
      if (threat) onSelectThreat(threat.id)
    },
    [threats, onSelectThreat]
  )

  // Select another threat and open its modal (from a countermeasure's "Mitigates" links).
  const openThreatByBackendId = useCallback(
    (backendThreatId: number) => {
      const threat = threats.find((candidate) => candidate.backendThreatId === backendThreatId)
      if (!threat) return
      onSelectThreat(threat.id)
      onOpenThreatChange?.(threat.displayNumber)
    },
    [threats, onSelectThreat, onOpenThreatChange]
  )

  const handleUnlinkThreat = (threat: AnalysisThreat) => {
    if (!selectedAbuseCase) return
    unlinkThreat.mutate(
      { abuseCaseId: selectedAbuseCase.id, threatId: threat.backendThreatId },
      {
        onSuccess: () => toast.success('Threat unlinked from the abuse case'),
        onError: (error) => toast.error(errorMessages(error, 'Could not unlink the threat')[0]),
      }
    )
  }

  const handleConfirmDeleteAbuseCase = () => {
    if (!deleteAbuseCaseFor) return
    const deleted = deleteAbuseCaseFor
    deleteAbuseCase.mutate(deleted.id, {
      onSuccess: () => {
        toast.success('Abuse case deleted')
        setDeleteAbuseCaseFor(null)
        // Stay on the use case (or the "Not linked" group) the deleted abuse case was listed under.
        if (selection?.kind === 'abuseCase' && selection.abuseCaseId === deleted.id) {
          onSelectionChange(
            columnEntry?.kind === 'useCase' ? { kind: 'useCase', useCaseId: columnEntry.useCaseId } : columnEntry ? { kind: 'noUseCase' } : null
          )
        }
      },
      onError: () => toast.error('Could not delete the abuse case'),
    })
  }

  const columnEntryUseCaseId = columnEntry?.kind === 'useCase' ? columnEntry.useCaseId : null

  const renderAbuseCaseRow = (abuseCase: AbuseCase) => {
    const isSelected = selection?.kind === 'abuseCase' && selection.abuseCaseId === abuseCase.id
    const isShared = abuseCase.useCases.length > 1
    const actionClass = cn(
      'h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground',
      isSelected ? '' : 'opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100'
    )
    return (
      <ColumnRow
        key={abuseCase.id}
        isSelected={isSelected}
        onSelect={() => onSelectionChange({ kind: 'abuseCase', abuseCaseId: abuseCase.id, useCaseId: columnEntryUseCaseId })}
        testKey={`abuse-case-${abuseCase.id}`}
      >
        <div className="flex items-center gap-1.5">
          <span className="min-w-0 flex-1 truncate text-sm">{abuseCase.name}</span>
          {isShared && (
            <Badge
              variant="outline"
              className="shrink-0 px-1 py-0 text-[10px] font-normal"
              title={`Misuses ${abuseCase.useCases.map((useCase) => useCase.name).join(', ')}`}
            >
              shared
            </Badge>
          )}
          {abuseCaseHasNoThreat(abuseCase) && (
            <Badge variant="outline" className={GAP_BADGE_CLASS}>
              No threat
            </Badge>
          )}
          <Button
            variant="ghost"
            size="icon"
            className={actionClass}
            onClick={(event) => {
              event.stopPropagation()
              openAbuseCaseDialog({ mode: 'edit', abuseCase })
            }}
            title="Edit abuse case"
            aria-label={`Edit ${abuseCase.name}`}
          >
            <Pencil className="h-3 w-3" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className={cn(actionClass, 'hover:text-destructive')}
            onClick={(event) => {
              event.stopPropagation()
              setDeleteAbuseCaseFor(abuseCase)
            }}
            title="Delete abuse case"
            aria-label={`Delete ${abuseCase.name}`}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </ColumnRow>
    )
  }

  // Threat actions sit in the center column, as in the component view; the
  // tree only selects and edits the structure.
  const threatActions = (abuseCase: AbuseCase) => (
    <div className="flex items-center gap-1">
      <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={() => setAddThreatFor(abuseCase)}>
        <Plus className="h-3 w-3" />
        Add
      </Button>
      <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={() => openLinkThreatDialog(abuseCase)}>
        <Link2 className="h-3 w-3" />
        Link existing
      </Button>
    </div>
  )

  const renderUnlinkedRealizes = (entry: UnlinkedRealizes, abuseCase: AbuseCase) => (
    <div
      key={entry.libraryThreatId ?? entry.ref ?? entry.name}
      className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground"
      data-testid="unlinked-realizes"
    >
      <span>Realizes library threat {entry.name}, not linked to a threat in this model.</span>
      <button type="button" className="text-blue-600 hover:underline" onClick={() => openLinkThreatDialog(abuseCase)}>
        Link a threat
      </button>
    </div>
  )

  return (
    <div className="h-full min-h-0 flex-1 overflow-hidden">
      <ResizablePanelGroup orientation="horizontal">
        {/* Column 1: use cases */}
        <ResizablePanel defaultSize="19%" minSize="12%" maxSize="30%">
          <div className="flex h-full flex-col">
            <ColumnHeader
              step={1}
              title="Use cases"
              actions={
                <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={() => setUseCaseDialogOpen(true)}>
                  <Plus className="h-3 w-3" />
                  Add
                </Button>
              }
            >
              What the system is for
            </ColumnHeader>
            <ScrollArea className="flex-1">
              <div className="space-y-0.5 p-2" data-testid="use-case-column">
                {useCases.length === 0 && (
                  <div className="space-y-3 px-2 py-6 text-center">
                    <p className="text-sm text-muted-foreground">
                      No use cases yet. Start with what the system is for, such as Place order.
                    </p>
                    <Button size="sm" className="gap-1" onClick={() => setUseCaseDialogOpen(true)}>
                      <Plus className="h-3 w-3" />
                      Add use case
                    </Button>
                  </div>
                )}
                {tree.useCaseNodes.map((node) => (
                  <ColumnRow
                    key={node.useCase.id}
                    isSelected={columnEntry?.kind === 'useCase' && columnEntry.useCaseId === node.useCase.id}
                    onSelect={() => onSelectionChange({ kind: 'useCase', useCaseId: node.useCase.id })}
                    testKey={`use-case-${node.useCase.id}`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="min-w-0 flex-1 truncate text-sm font-medium">{node.useCase.name}</span>
                      <span className="shrink-0 text-xs text-muted-foreground" title="Abuse cases">
                        {node.abuseCases.length}
                      </span>
                    </div>
                    {node.gaps.length > 0 && (
                      <div className="mt-0.5 flex flex-wrap gap-1">
                        {node.gaps.map((gap) => (
                          <Badge key={gap} variant="outline" className={GAP_BADGE_CLASS}>
                            {USE_CASE_GAP_LABELS[gap]}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </ColumnRow>
                ))}
                {tree.unlinkedAbuseCases.length > 0 && (
                  <div className="mt-2 border-t pt-2">
                    <ColumnRow
                      isSelected={columnEntry?.kind === 'noUseCase'}
                      onSelect={() => onSelectionChange({ kind: 'noUseCase' })}
                      testKey="not-linked-to-use-case"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="min-w-0 flex-1 truncate text-sm italic text-muted-foreground">
                          Not linked to a use case
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">{tree.unlinkedAbuseCases.length}</span>
                      </div>
                    </ColumnRow>
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

        {/* Column 2: abuse cases of the use case */}
        <ResizablePanel defaultSize="21%" minSize="12%" maxSize="35%">
          <div className="flex h-full flex-col">
            <ColumnHeader
              step={2}
              title="Abuse cases"
              actions={
                columnEntry && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 gap-1 text-xs"
                    onClick={() => openAbuseCaseDialog({ mode: 'create', useCaseId: columnEntryUseCaseId ?? undefined })}
                  >
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                )
              }
            >
              <span data-testid="abuse-case-column-label">
                {columnUseCase
                  ? `How ${columnUseCase.name} can be misused`
                  : columnEntry?.kind === 'noUseCase'
                    ? 'Not linked to a use case'
                    : 'Select a use case'}
              </span>
            </ColumnHeader>
            <ScrollArea className="flex-1">
              <div className="space-y-0.5 p-2" data-testid="abuse-case-column">
                {columnAbuseCases.map(renderAbuseCaseRow)}
                {columnEntry && columnAbuseCases.length === 0 && (
                  <div className="space-y-3 px-2 py-6 text-center">
                    <p className="text-sm text-muted-foreground">
                      No abuse cases yet. Ask how someone could misuse {columnUseCase?.name ?? 'this'}.
                    </p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1"
                      onClick={() => openAbuseCaseDialog({ mode: 'create', useCaseId: columnEntryUseCaseId ?? undefined })}
                    >
                      <Plus className="h-3 w-3" />
                      Add abuse case
                    </Button>
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

        {/* Column 3: threats of the abuse case */}
        <ResizablePanel defaultSize="30%" minSize="18%" maxSize="50%">
          <div className="flex h-full flex-col">
            <ColumnHeader
              step={3}
              title="Threats"
              actions={
                selectedAbuseCase && (
                  <>
                    {activeCount > 0 && (
                      <Badge variant="outline" className="text-xs">
                        {activeCount} active
                      </Badge>
                    )}
                    {threatActions(selectedAbuseCase)}
                  </>
                )
              }
            >
              <span data-testid="selection-label">{selectionLabel}</span>
              {selectedAbuseCase?.description && (
                <p className="mt-1" data-testid="abuse-case-description">
                  {selectedAbuseCase.description}
                </p>
              )}
            </ColumnHeader>

            {selectedAbuseCase && selectedAbuseCase.unlinkedRealizes.length > 0 && (
              <div className="space-y-1 border-b px-3 py-2">
                {selectedAbuseCase.unlinkedRealizes.map((entry) => renderUnlinkedRealizes(entry, selectedAbuseCase))}
              </div>
            )}

            <ThreatList
              threatModelId={threatModelId}
              threats={threatsOfSelection}
              hasSelection={selectedAbuseCase !== null}
              selectedThreatId={selectedThreatId}
              onSelectThreat={onSelectThreat}
              openThreatNumber={openThreatNumber}
              onOpenThreatChange={onOpenThreatChange}
              onUpdateTriageStatus={onUpdateTriageStatus}
              onOpenAbuseCase={onOpenAbuseCase}
              onUnlink={selectedAbuseCase ? handleUnlinkThreat : undefined}
              unlinkLabel="Unlink from abuse case"
              emptyActions={
                selectedAbuseCase ? (
                  <div className="space-y-3">
                    <p className="mx-auto max-w-sm text-xs">
                      Link the threats this abuse case leads to. You rate those and add countermeasures.
                    </p>
                    <div className="flex justify-center">{threatActions(selectedAbuseCase)}</div>
                  </div>
                ) : undefined
              }
            />
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

        {/* Column 3: the countermeasures of the selected threat */}
        <CountermeasureColumn
          threatModelId={threatModelId}
          threats={threats}
          selectedThreat={selectedThreat}
          onSelectThreatByBackendId={selectThreatByBackendId}
          onOpenThreatByBackendId={openThreatByBackendId}
          openCountermeasureNumber={openCountermeasureNumber}
          onOpenCountermeasureChange={onOpenCountermeasureChange}
          onCountermeasureStatusChange={onCountermeasureStatusChange}
          onAssignOwner={onAssignOwner}
          onAddCustomCountermeasure={onAddCustomCountermeasure}
          onCountermeasurePriorityChange={onCountermeasurePriorityChange}
          onCountermeasureDueDateChange={onCountermeasureDueDateChange}
          onCountermeasureExternalTicketChange={onCountermeasureExternalTicketChange}
          onReorderCountermeasures={onReorderCountermeasures}
          isSecurityTeam={isSecurityTeam}
          stepNumber={4}
        />
      </ResizablePanelGroup>

      <UseCaseDialog
        threatModelId={threatModelId}
        open={useCaseDialogOpen}
        onOpenChange={setUseCaseDialogOpen}
        onSaved={(saved) => onSelectionChange({ kind: 'useCase', useCaseId: saved.id })}
      />

      <AbuseCaseDialog
        threatModelId={threatModelId}
        open={abuseCaseDialogOpen}
        onOpenChange={setAbuseCaseDialogOpen}
        abuseCase={abuseCaseDialog?.mode === 'edit' ? abuseCaseDialog.abuseCase : undefined}
        defaultUseCaseId={abuseCaseDialog?.mode === 'create' ? abuseCaseDialog.useCaseId : undefined}
        onSaved={(saved) => {
          if (abuseCaseDialog?.mode === 'create') {
            onSelectionChange({ kind: 'abuseCase', abuseCaseId: saved.id, useCaseId: abuseCaseDialog.useCaseId ?? null })
          }
        }}
      />

      {addThreatFor && addThreatPreset && (
        <AddThreatDialog
          open
          onOpenChange={(open) => {
            if (!open) setAddThreatFor(null)
          }}
          threatModelId={threatModelId}
          initialTargets={addThreatPreset.initialTargets}
          initialWholeSystem={false}
          suggestedTargets={addThreatPreset.suggestedTargets}
          initialActor={addThreatPreset.initialActor}
          abuseCaseIds={[addThreatFor.id]}
          targetName={addThreatFor.name}
        />
      )}

      <LinkThreatDialog
        threatModelId={threatModelId}
        abuseCase={linkThreatFor}
        threats={allThreats}
        open={linkThreatOpen}
        onOpenChange={setLinkThreatOpen}
      />

      <AlertDialog
        open={deleteAbuseCaseFor !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteAbuseCaseFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete abuse case?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes "{deleteAbuseCaseFor?.name}". Its threats stay in the model. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteAbuseCase.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDeleteAbuseCase()
              }}
              disabled={deleteAbuseCase.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteAbuseCase.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Deleting
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
