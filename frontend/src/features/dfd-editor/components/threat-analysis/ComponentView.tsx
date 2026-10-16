/**
 * The threat analysis screen (plan 11.3): the analysis tree, the scenarios
 * of the selection, and the countermeasures of the selected scenario.
 *
 * A scenario has targets or is whole-system; it shows under each target
 * with a "shared" mark and "Also on" links, and every edit applies to the
 * one scenario. Zones and boundaries are selectable and list the controls
 * scoped to them (a plain list, L4). Rows come from the backend, so targets
 * on no canvas show too.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Loader2, Plus } from 'lucide-react'
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
import { useThreatModel } from '@/features/threat-models/api/threat-models'
import { useAnalysisComponents, useZones } from '@/features/threat-models/api/components'
import { useFlows } from '@/features/threat-models/api/flows'
import { useBoundaries } from '@/features/threat-models/api/boundaries'
import { showDeleteWarnings } from '@/features/threat-models/api/delete-warnings'
import { useCountermeasures, useDeleteComponent, useThreatModelThreats } from '@/features/threat-models/api/threats'
import { isActiveThreat, type TriageStatus } from '@/types/triage'
import type { AnalysisCountermeasure, AnalysisThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { AnalysisTreeItem } from './ComponentTreeItem'
import { ThreatList } from './ThreatList'
import { CountermeasureColumn } from './CountermeasureColumn'
import { type Assignee } from './CountermeasureCard'
import { NumberBadge } from './NumberBadge'
import { buildAnalysisTree, initialAnalysisSelection, type AnalysisTreeNode } from './hierarchy-utils'
import {
  TARGET_TYPE_LABELS,
  targetSelection,
  threatMatchesSelection,
  type AnalysisSelection,
} from './analysis-selection'

export type { Assignee }

export interface ComponentViewProps {
  threatModelId: string
  /** The scenarios shown (the page may filter them by diagram). */
  threats: AnalysisThreat[]
  selection: AnalysisSelection | null
  selectedThreatId: string | null
  selectedThreat: AnalysisThreat | null
  onSelectTarget: (selection: AnalysisSelection) => void
  onSelectThreat: (threatId: string) => void
  /** The display numbers of the open threat and countermeasure modals (the page keeps them in the URL). */
  openThreatNumber?: string | null
  onOpenThreatChange?: (displayNumber: string | null) => void
  openCountermeasureNumber?: string | null
  onOpenCountermeasureChange?: (displayNumber: string | null) => void
  /** Open an abuse case in the "By use case" view (from a threat's "From abuse cases" links). */
  onOpenAbuseCase?: (abuseCaseId: number) => void
  onCountermeasureStatusChange: (
    threatUiId: string,
    countermeasureId: string,
    status: CountermeasureStatus,
    notes?: string
  ) => void
  onAssignOwner: (threatUiId: string, countermeasureId: string, assignee: Assignee, newStatus?: CountermeasureStatus) => void
  onAddComponent: () => void
  onAddCustomThreat: () => void
  onUpdateTriageStatus: (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  onAddCustomCountermeasure: () => void
  onCountermeasurePriorityChange: (threatUiId: string, countermeasureId: string, priority: AnalysisCountermeasure['priority']) => void
  onCountermeasureDueDateChange: (threatUiId: string, countermeasureId: string, dueDate: string | null) => void
  onCountermeasureExternalTicketChange: (threatUiId: string, countermeasureId: string, externalTicketUrl: string) => void
  onReorderThreats?: (selection: AnalysisSelection, reorderedThreats: AnalysisThreat[]) => void
  onReorderCountermeasures?: (threatUiId: string, reorderedCountermeasures: AnalysisCountermeasure[]) => void
  isSecurityTeam?: boolean
}

/** The label of a selection, from the tree row that holds it. */
function selectionLabel(selection: AnalysisSelection | null, byKey: Map<string, AnalysisTreeNode>): string {
  if (!selection) return 'Select the system, a component, a flow, a zone or a boundary'
  if (selection.kind === 'system') return 'System'
  const node = byKey.get(`${selection.type}-${selection.id}`)
  return node ? `${node.label} (${TARGET_TYPE_LABELS[selection.type]})` : `${TARGET_TYPE_LABELS[selection.type]} ${selection.id}`
}

export function ComponentView({
  threatModelId,
  threats,
  selection,
  selectedThreatId,
  selectedThreat,
  onSelectTarget,
  onSelectThreat,
  openThreatNumber,
  onOpenThreatChange,
  openCountermeasureNumber,
  onOpenCountermeasureChange,
  onOpenAbuseCase,
  onCountermeasureStatusChange,
  onAssignOwner,
  onAddComponent,
  onAddCustomThreat,
  onUpdateTriageStatus,
  onAddCustomCountermeasure,
  onCountermeasurePriorityChange,
  onCountermeasureDueDateChange,
  onCountermeasureExternalTicketChange,
  onReorderThreats,
  onReorderCountermeasures,
  isSecurityTeam,
}: ComponentViewProps) {
  const [collapsedKeys, setCollapsedKeys] = useState<Set<string>>(new Set())
  const [deleteComponentConfirmFor, setDeleteComponentConfirmFor] = useState<{ id: number; name: string } | null>(null)

  // The model's rows, canvas or not.
  const { data: threatModel } = useThreatModel(threatModelId)
  const { data: components = [], isSuccess: componentsLoaded } = useAnalysisComponents(threatModelId)
  const { data: zones = [], isSuccess: zonesLoaded } = useZones({ threatModel: threatModelId })
  const { data: flows = [], isSuccess: flowsLoaded } = useFlows({ threatModel: threatModelId })
  const { data: boundaries = [], isSuccess: boundariesLoaded } = useBoundaries({ threatModel: threatModelId })
  const { data: analysisPayload } = useThreatModelThreats(threatModelId)
  const { data: allCountermeasures = [] } = useCountermeasures({ threatModel: threatModelId })

  const deleteComponentMutation = useDeleteComponent()

  // Components on some canvas cannot be deleted here (they are deleted where drawn).
  const onCanvasComponentIds = useMemo(() => {
    const ids = new Set<number>()
    for (const entry of Object.values(analysisPayload?.nodeComponentMap ?? {})) {
      if (!entry.isAnalysisOnly) ids.add(entry.componentId)
    }
    return ids
  }, [analysisPayload?.nodeComponentMap])

  const tree = useMemo(
    () =>
      buildAnalysisTree({
        blueprints: (threatModel?.blueprints ?? []).map((blueprint) => ({
          id: blueprint.id,
          name: blueprint.name,
          displayOrder: blueprint.displayOrder,
        })),
        components: components.map((component) => ({
          id: component.id,
          name: component.name,
          blueprint: component.blueprint,
          zone: component.zone,
          parentComponent: component.parentComponent,
          category: component.category,
          componentLibraryName: component.componentLibraryName,
          isAnalysisOnly: !onCanvasComponentIds.has(component.id),
        })),
        zones: zones.map((zone) => ({
          id: zone.id,
          name: zone.name,
          blueprint: zone.blueprint,
          parent: zone.parent,
          zoneType: zone.zoneType,
          trustLevel: zone.trustLevel,
        })),
        flows: flows.map((flow) => ({
          id: flow.id,
          blueprint: flow.blueprint,
          label: flow.label,
          sourceComponentName: flow.sourceComponentName,
          destComponentName: flow.destComponentName,
        })),
        boundaries: boundaries.map((boundary) => ({
          id: boundary.id,
          blueprint: boundary.blueprint,
          label: boundary.label,
          zoneAName: boundary.zoneAName,
          zoneBName: boundary.zoneBName,
        })),
        threats,
      }),
    [threatModel?.blueprints, components, zones, flows, boundaries, threats, onCanvasComponentIds]
  )

  const toggleCollapsed = useCallback((key: string) => {
    setCollapsedKeys((previous) => {
      const next = new Set(previous)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  const threatsForSelection = useMemo(
    () => threats.filter((threat) => threatMatchesSelection(threat, selection)),
    [threats, selection]
  )
  const activeSelectionThreatCount = threatsForSelection.filter((threat) => isActiveThreat(threat.triageStatus)).length

  // Controls scoped to the selected zone or boundary (a plain list, L4).
  const scopedCountermeasures = useMemo(() => {
    if (!selection || selection.kind !== 'target' || (selection.type !== 'zone' && selection.type !== 'boundary')) {
      return []
    }
    return allCountermeasures.filter((countermeasure) =>
      countermeasure.targets.some((target) => target.type === selection.type && target.id === selection.id)
    )
  }, [allCountermeasures, selection])

  const activeThreatCount = threats.filter((threat) => isActiveThreat(threat.triageStatus)).length
  const selectThreatByBackendId = useCallback(
    (backendThreatId: number) => {
      const threat = threats.find((candidate) => candidate.backendThreatId === backendThreatId)
      if (!threat) return
      const firstTarget = threat.targets[0]
      const nextSelection: AnalysisSelection = threat.wholeSystem || !firstTarget
        ? { kind: 'system' }
        : targetSelection(firstTarget.type, firstTarget.id)
      if (!threatMatchesSelection(threat, selection)) onSelectTarget(nextSelection)
      onSelectThreat(threat.id)
    },
    [threats, selection, onSelectTarget, onSelectThreat]
  )

  // Select another threat and open its modal (from a countermeasure's "Mitigates" links).
  const openThreatByBackendId = useCallback(
    (backendThreatId: number) => {
      selectThreatByBackendId(backendThreatId)
      const threat = threats.find((candidate) => candidate.backendThreatId === backendThreatId)
      if (threat && onOpenThreatChange) onOpenThreatChange(threat.displayNumber)
    },
    [threats, selectThreatByBackendId, onOpenThreatChange]
  )

  // Never open on two empty panes: with nothing selected, start on the first
  // row that has a threat (the system, then components in tree order). Waits
  // until the tree's rows have loaded, so the start does not fall back to the
  // system just because the components are still on their way.
  // The page derives `threats` from the payload one render later, so wait for that too.
  const threatsHaveArrived = analysisPayload !== undefined && (analysisPayload.analysisThreats.length === 0 || threats.length > 0)
  const treeIsReady =
    threatModel !== undefined &&
    threatsHaveArrived &&
    componentsLoaded &&
    zonesLoaded &&
    flowsLoaded &&
    boundariesLoaded
  useEffect(() => {
    if (selection === null && treeIsReady) onSelectTarget(initialAnalysisSelection(tree.root))
  }, [selection, treeIsReady, tree.root, onSelectTarget])

  const handleConfirmDeleteComponent = () => {
    if (!deleteComponentConfirmFor) return
    deleteComponentMutation.mutate(deleteComponentConfirmFor.id, {
      onSuccess: (warnings) => {
        toast.success('Component deleted')
        showDeleteWarnings(warnings)
        setDeleteComponentConfirmFor(null)
      },
      onError: () => toast.error('Could not delete the component'),
    })
  }

  const selectedLabel = selectionLabel(selection, tree.byKey)
  const selectionIsZoneOrBoundary =
    selection?.kind === 'target' && (selection.type === 'zone' || selection.type === 'boundary')

  return (
    <div className="h-full min-h-0 flex-1 overflow-hidden">
      <ResizablePanelGroup orientation="horizontal">
        {/* Column 1: the tree */}
        <ResizablePanel defaultSize="22%" minSize="12%" maxSize="35%">
          <div className="flex h-full flex-col">
            <div className="border-b px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="font-medium">Tree</div>
                <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={onAddComponent}>
                  <Plus className="h-3 w-3" />
                  Add
                </Button>
              </div>
              <div className="text-xs text-muted-foreground">
                {components.length} components, {zones.length} zones, {flows.length} flows, {boundaries.length} boundaries,{' '}
                {activeThreatCount} threats
              </div>
            </div>
            <ScrollArea className="flex-1">
              <div className="space-y-0.5 p-2" data-testid="analysis-tree">
                <AnalysisTreeItem
                  node={tree.root}
                  selection={selection}
                  collapsedKeys={collapsedKeys}
                  onSelect={onSelectTarget}
                  onToggleCollapsed={toggleCollapsed}
                  onRequestDeleteComponent={setDeleteComponentConfirmFor}
                />
              </div>
            </ScrollArea>
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

        {/* Column 2: the scenarios of the selection */}
        <ResizablePanel defaultSize="36%" minSize="20%" maxSize="55%">
          <div className="flex h-full flex-col">
            <div className="border-b px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="font-medium">Threats</div>
                <div className="flex items-center gap-2">
                  {activeSelectionThreatCount > 0 && (
                    <Badge variant="outline" className="text-xs">
                      {activeSelectionThreatCount} active
                    </Badge>
                  )}
                  {selection && (
                    <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={onAddCustomThreat}>
                      <Plus className="h-3 w-3" />
                      Add
                    </Button>
                  )}
                </div>
              </div>
              <div className="text-xs text-muted-foreground" data-testid="selection-label">
                {selectedLabel}
              </div>
            </div>

            {selectionIsZoneOrBoundary && (
              <div className="border-b px-3 py-2 text-xs">
                <div className="font-medium text-muted-foreground">Controls scoped here</div>
                {scopedCountermeasures.length === 0 ? (
                  <p className="mt-0.5 text-muted-foreground">None. A control's scope is a label; it changes no threat status.</p>
                ) : (
                  <ul className="mt-1 space-y-0.5">
                    {scopedCountermeasures.map((countermeasure) => (
                      <li key={countermeasure.id} className="flex items-center gap-1.5">
                        <NumberBadge number={countermeasure.displayNumber} />
                        <span className="truncate">{countermeasure.countermeasureNameDisplay}</span>
                        <span className="text-muted-foreground">({countermeasure.status.replace('_', ' ')})</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            <ThreatList
              threatModelId={threatModelId}
              threats={threatsForSelection}
              hasSelection={selection !== null}
              selection={selection}
              selectedThreatId={selectedThreatId}
              onSelectThreat={onSelectThreat}
              openThreatNumber={openThreatNumber}
              onOpenThreatChange={onOpenThreatChange}
              onSelectTarget={onSelectTarget}
              onOpenAbuseCase={onOpenAbuseCase}
              onUpdateTriageStatus={onUpdateTriageStatus}
              onReorder={(reordered) => {
                if (selection && onReorderThreats) onReorderThreats(selection, reordered)
              }}
              onTargetsSaved={(wholeSystem) => {
                if (wholeSystem) onSelectTarget({ kind: 'system' })
              }}
            />
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

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
        />
      </ResizablePanelGroup>

      <AlertDialog
        open={!!deleteComponentConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteComponentConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete component?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes {deleteComponentConfirmFor?.name || 'this component'}. A threat whose only target it was goes with
              it; a threat with other targets just loses this one. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteComponentMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDeleteComponent()
              }}
              disabled={deleteComponentMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteComponentMutation.isPending ? (
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
