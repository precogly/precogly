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

import { useCallback, useMemo, useState } from 'react'
import { toast } from 'sonner'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Crosshair,
  GripVertical,
  Loader2,
  Lock,
  Pencil,
  Plus,
  Trash2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { SortableList } from '@/components/shared/SortableList'
import { RatingBadge } from '@/features/threat-models/components/rating'
import { useThreatModel } from '@/features/threat-models/api/threat-models'
import { useAnalysisComponents, useZones } from '@/features/threat-models/api/components'
import { useFlows } from '@/features/threat-models/api/flows'
import { useBoundaries } from '@/features/threat-models/api/boundaries'
import { showDeleteWarnings } from '@/features/threat-models/api/delete-warnings'
import {
  useCountermeasures,
  useDeleteComponent,
  useDeleteCountermeasure,
  useDeleteThreat,
  useSetThreatTargets,
  useThreatModelThreats,
  useThreatPersonas,
  useUnlinkCountermeasure,
  useUpdateThreat,
  type TargetRef,
} from '@/features/threat-models/api/threats'
import { isActiveThreat, TRIAGE_STATUS_COLORS, TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import type { TaxonomyEntry } from '@/types/domain'
import type {
  AnalysisCountermeasure,
  AnalysisThreat,
  ComplianceStandardMapping,
  CountermeasureStatus,
  ThreatStatus,
} from '../../types/threat-analysis'
import { deriveThreatStatus, THREAT_STATUS_CONFIG } from '../../types/threat-analysis'
import { EditComplianceMappingsDialog } from './EditComplianceMappingsDialog'
import { EditTaxonomyMappingsDialog } from './EditTaxonomyMappingsDialog'
import { EditTargetsDialog } from './EditTargetsDialog'
import { AnalysisTreeItem } from './ComponentTreeItem'
import { ThreatDetailPanel } from './ThreatDetailPanel'
import { CountermeasureCard, type Assignee } from './CountermeasureCard'
import { UnattachedControlsBlock } from './UnattachedControlsBlock'
import { NumberBadge } from './NumberBadge'
import { buildAnalysisTree, type AnalysisTreeNode } from './hierarchy-utils'
import {
  TARGET_TYPE_LABELS,
  isSameSelection,
  targetSelection,
  threatMatchesSelection,
  type AnalysisSelection,
} from './analysis-selection'
import { formatTargetList } from './countermeasure-utils'

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

function ThreatStatusBadge({ status }: { status: ThreatStatus }) {
  const config = THREAT_STATUS_CONFIG[status]
  return (
    <Badge variant="outline" className={cn('text-xs', config.bgColor)}>
      {config.label}
    </Badge>
  )
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
  const [showTriagedThreats, setShowTriagedThreats] = useState(false)
  const [pendingTriageFor, setPendingTriageFor] = useState<{ threatId: string; status: TriageStatus } | null>(null)
  const [triageRationale, setTriageRationale] = useState('')
  const [collapsedKeys, setCollapsedKeys] = useState<Set<string>>(new Set())
  const [editingComplianceFor, setEditingComplianceFor] = useState<{
    backendId: number
    name: string
    mappings: ComplianceStandardMapping[]
  } | null>(null)
  const [editingTaxonomyFor, setEditingTaxonomyFor] = useState<{
    backendId: number
    name: string
    libraryEntries: TaxonomyEntry[]
  } | null>(null)
  const [deleteCountermeasureConfirmFor, setDeleteCountermeasureConfirmFor] = useState<{
    name: string
    backendId: number
    isShared?: boolean
    threatId: number
  } | null>(null)
  const [deleteComponentConfirmFor, setDeleteComponentConfirmFor] = useState<{ id: number; name: string } | null>(null)
  const [deleteThreatConfirmFor, setDeleteThreatConfirmFor] = useState<{ backendId: number; name: string } | null>(null)
  const [editingThreatFor, setEditingThreatFor] = useState<{ backendId: number; name: string; description: string } | null>(
    null
  )
  const [editThreatName, setEditThreatName] = useState('')
  const [editThreatDescription, setEditThreatDescription] = useState('')
  const [editingTargetsFor, setEditingTargetsFor] = useState<AnalysisThreat | null>(null)

  // The model's rows, canvas or not.
  const { data: threatModel } = useThreatModel(threatModelId)
  const { data: components = [] } = useAnalysisComponents(threatModelId)
  const { data: zones = [] } = useZones({ threatModel: threatModelId })
  const { data: flows = [] } = useFlows({ threatModel: threatModelId })
  const { data: boundaries = [] } = useBoundaries({ threatModel: threatModelId })
  const { data: analysisPayload } = useThreatModelThreats(threatModelId)
  const { data: allCountermeasures = [] } = useCountermeasures({ threatModel: threatModelId })
  const { data: personas = [] } = useThreatPersonas(threatModelId)

  const updateThreatMutation = useUpdateThreat()
  const setThreatTargetsMutation = useSetThreatTargets()
  const deleteCountermeasureMutation = useDeleteCountermeasure()
  const unlinkCountermeasureMutation = useUnlinkCountermeasure()
  const deleteComponentMutation = useDeleteComponent()
  const deleteThreatMutation = useDeleteThreat()

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
  const activeThreats = useMemo(
    () =>
      threatsForSelection
        .filter((threat) => isActiveThreat(threat.triageStatus))
        .sort((left, right) => (left.displayOrder ?? 0) - (right.displayOrder ?? 0) || left.number - right.number),
    [threatsForSelection]
  )
  const triagedThreats = threatsForSelection.filter((threat) => !isActiveThreat(threat.triageStatus))

  // Controls scoped to the selected zone or boundary (a plain list, L4).
  const scopedCountermeasures = useMemo(() => {
    if (!selection || selection.kind !== 'target' || (selection.type !== 'zone' && selection.type !== 'boundary')) {
      return []
    }
    return allCountermeasures.filter((countermeasure) =>
      countermeasure.targets.some((target) => target.type === selection.type && target.id === selection.id)
    )
  }, [allCountermeasures, selection])

  const sortedCountermeasures = useMemo(
    () =>
      [...(selectedThreat?.countermeasures ?? [])].sort((left, right) => (left.displayOrder ?? 0) - (right.displayOrder ?? 0)),
    [selectedThreat?.countermeasures]
  )
  const totalCountermeasures = selectedThreat?.countermeasures.length ?? 0
  const resolvedCountermeasures = selectedThreat?.countermeasures.filter((countermeasure) => countermeasure.status !== 'gap').length ?? 0

  const activeThreatCount = threats.filter((threat) => isActiveThreat(threat.triageStatus)).length
  const modelSummary = useMemo(
    () =>
      threats.reduce(
        (summary, threat) => {
          if (!isActiveThreat(threat.triageStatus)) return summary
          const status = deriveThreatStatus(threat.countermeasures)
          if (status === 'exposed') summary.exposed += 1
          else if (status === 'addressable') summary.addressable += 1
          return summary
        },
        { exposed: 0, addressable: 0 }
      ),
    [threats]
  )

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

  const handleSaveEditThreat = () => {
    if (!editingThreatFor || !editThreatName.trim()) return
    updateThreatMutation.mutate(
      {
        threatId: editingThreatFor.backendId,
        data: { threatName: editThreatName.trim(), threatDescription: editThreatDescription.trim() },
      },
      {
        onSuccess: () => {
          toast.success('Threat updated')
          setEditingThreatFor(null)
        },
        onError: () => toast.error('Could not update the threat'),
      }
    )
  }

  const handleConfirmDeleteCountermeasure = () => {
    if (!deleteCountermeasureConfirmFor) return
    const { isShared, backendId, threatId } = deleteCountermeasureConfirmFor
    const onSuccess = () => {
      toast.success(isShared ? 'Countermeasure unlinked' : 'Countermeasure removed')
      setDeleteCountermeasureConfirmFor(null)
    }
    const onError = () => toast.error(isShared ? 'Could not unlink the countermeasure' : 'Could not remove the countermeasure')
    unlinkCountermeasureMutation.mutate({ countermeasureId: backendId, threatId }, { onSuccess, onError })
  }

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

  const handleConfirmDeleteThreat = () => {
    if (!deleteThreatConfirmFor) return
    deleteThreatMutation.mutate(deleteThreatConfirmFor.backendId, {
      onSuccess: () => {
        toast.success('Threat deleted')
        setDeleteThreatConfirmFor(null)
        setEditingTargetsFor(null)
      },
      onError: () => toast.error('Could not delete the threat'),
    })
  }

  const handleSaveTargets = (targets: TargetRef[], wholeSystem: boolean) => {
    if (!editingTargetsFor) return
    setThreatTargetsMutation.mutate(
      { threatId: editingTargetsFor.backendThreatId, targets, wholeSystem },
      {
        onSuccess: () => {
          toast.success(wholeSystem ? 'Now a whole-system threat' : 'Targets saved')
          setEditingTargetsFor(null)
          if (wholeSystem) onSelectTarget({ kind: 'system' })
        },
        onError: () => toast.error('Could not save the targets'),
      }
    )
  }

  const confirmTriage = (threatUiId: string, status: TriageStatus) => {
    onUpdateTriageStatus(threatUiId, status, triageRationale.trim())
    setPendingTriageFor(null)
    setTriageRationale('')
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
              {modelSummary.exposed > 0 ? (
                <Badge variant="outline" className="mt-1 bg-red-100 text-xs text-red-700">
                  {modelSummary.exposed} exposed
                </Badge>
              ) : modelSummary.addressable > 0 ? (
                <Badge variant="outline" className="mt-1 bg-yellow-100 text-xs text-yellow-700">
                  {modelSummary.addressable} in progress
                </Badge>
              ) : null}
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
                  {activeThreats.length > 0 && (
                    <Badge variant="outline" className="text-xs">
                      {activeThreats.length} active
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

            <ScrollArea className="flex-1">
              <div className="space-y-1 p-2">
                {activeThreats.length > 0 && (
                  <div>
                    <p className="mb-1 px-2 py-1 text-xs text-muted-foreground">
                      Triage, rate or delete threats. A change here shows under every target of the threat.
                    </p>
                    <SortableList
                      items={activeThreats}
                      getItemId={(threat) => threat.id}
                      onReorder={(reordered) => {
                        if (selection && onReorderThreats) onReorderThreats(selection, reordered)
                      }}
                      renderItem={(threat, dragHandleRef) => {
                        const status = deriveThreatStatus(threat.countermeasures)
                        const isSelected = threat.id === selectedThreatId
                        const isShared = threat.targets.length > 1
                        const otherTargets = threat.targets.filter(
                          (target) => !isSameSelection(targetSelection(target.type, target.id), selection)
                        )
                        return (
                          <div
                            className={cn(
                              'group rounded-md p-2 transition-colors',
                              isSelected ? 'border border-slate-300 bg-slate-100' : 'hover:bg-slate-50'
                            )}
                            data-threat-number={threat.displayNumber}
                          >
                            <div className="flex items-center gap-1">
                              <div
                                ref={dragHandleRef}
                                className="shrink-0 cursor-grab opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100"
                              >
                                <GripVertical className="h-4 w-4 text-muted-foreground" />
                              </div>
                              <div
                                role="button"
                                tabIndex={0}
                                onClick={() => onSelectThreat(threat.id)}
                                onKeyDown={(event) => {
                                  if (event.key === 'Enter' || event.key === ' ') onSelectThreat(threat.id)
                                }}
                                className="min-w-0 flex-1 cursor-pointer overflow-hidden text-left"
                              >
                                <div className="flex items-center gap-1.5">
                                  <span
                                    className="h-2 w-2 shrink-0 rounded-full"
                                    style={{ backgroundColor: THREAT_STATUS_CONFIG[status].color }}
                                  />
                                  <NumberBadge number={threat.displayNumber} />
                                  <span className="truncate text-sm font-medium">{threat.threatName || 'Unnamed threat'}</span>
                                  {isShared && (
                                    <Badge variant="outline" className="shrink-0 px-1 py-0 text-[10px] font-normal" title="On several targets">
                                      shared
                                    </Badge>
                                  )}
                                  {threat.wholeSystem && (
                                    <Badge variant="outline" className="shrink-0 px-1 py-0 text-[10px] font-normal">
                                      whole system
                                    </Badge>
                                  )}
                                </div>
                                {!isSelected && (
                                  <div className="ml-4 mt-1 flex items-center gap-1">
                                    <RatingBadge rating={threat.rating} size="sm" />
                                    <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={1} size="sm" />
                                  </div>
                                )}
                              </div>
                              <ThreatStatusBadge status={status} />
                              <Select
                                value={threat.triageStatus}
                                onValueChange={(value) => {
                                  const nextStatus = value as TriageStatus
                                  if (nextStatus === 'accept' || nextStatus === 'delegate' || nextStatus === 'eliminate') {
                                    setPendingTriageFor({ threatId: threat.id, status: nextStatus })
                                    setTriageRationale('')
                                  } else {
                                    onUpdateTriageStatus(threat.id, nextStatus)
                                  }
                                }}
                              >
                                <SelectTrigger
                                  className="h-6 w-[100px] shrink-0 text-xs"
                                  onClick={(event) => event.stopPropagation()}
                                  aria-label="Triage"
                                >
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  {TRIAGE_STATUSES.map((entry) => (
                                    <SelectItem key={entry.value} value={entry.value} className="text-xs">
                                      {entry.label}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100 touch:opacity-100"
                                onClick={(event) => {
                                  event.stopPropagation()
                                  setEditingTargetsFor(threat)
                                }}
                                title="Edit targets"
                                aria-label={`Edit targets of ${threat.displayNumber}`}
                              >
                                <Crosshair className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100 touch:opacity-100"
                                onClick={(event) => {
                                  event.stopPropagation()
                                  setEditingThreatFor({
                                    backendId: threat.backendThreatId,
                                    name: threat.threatName || '',
                                    description: threat.threatDescription || '',
                                  })
                                  setEditThreatName(threat.threatName || '')
                                  setEditThreatDescription(threat.threatDescription || '')
                                }}
                                title="Edit threat"
                                aria-label={`Edit ${threat.displayNumber}`}
                              >
                                <Pencil className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100 touch:opacity-100"
                                onClick={(event) => {
                                  event.stopPropagation()
                                  setDeleteThreatConfirmFor({
                                    backendId: threat.backendThreatId,
                                    name: threat.threatName || 'this threat',
                                  })
                                }}
                                title="Delete threat"
                                aria-label={`Delete ${threat.displayNumber}`}
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>

                            {(isShared || threat.libraryMismatch) && (
                              <div className="ml-4 mt-1 space-y-0.5 text-[11px] text-muted-foreground">
                                {isShared && otherTargets.length > 0 && (
                                  <div className="flex flex-wrap items-center gap-x-1">
                                    <span>Also on:</span>
                                    {otherTargets.map((target, index) => (
                                      <span key={`${target.type}-${target.id}`}>
                                        <button
                                          type="button"
                                          className="text-blue-600 hover:underline"
                                          onClick={() => onSelectTarget(targetSelection(target.type, target.id))}
                                        >
                                          {target.name || 'Unnamed'} ({TARGET_TYPE_LABELS[target.type]})
                                        </button>
                                        {index < otherTargets.length - 1 ? ',' : ''}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {threat.libraryMismatch && (
                                  <div className="flex items-center gap-1 text-amber-700">
                                    <AlertTriangle className="h-3 w-3 shrink-0" />
                                    The library no longer lists this threat here. It was kept because it has been edited.
                                  </div>
                                )}
                              </div>
                            )}

                            {isSelected && (
                              <div className="ml-4 mt-1 flex items-center gap-1">
                                <TaxonomyBadges entries={threat.taxonomyEntries} size="sm" />
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    setEditingTaxonomyFor({
                                      backendId: threat.backendThreatId,
                                      name: threat.threatName || '',
                                      libraryEntries: (threat.taxonomyEntries || []).filter(
                                        (entry) => entry.source === 'library' || !entry.source
                                      ),
                                    })
                                  }}
                                  title="Edit taxonomy entries"
                                >
                                  <Pencil className="h-3 w-3" />
                                </Button>
                              </div>
                            )}

                            {pendingTriageFor?.threatId === threat.id && (
                              <div
                                className="ml-4 mt-2 space-y-2 rounded-md border border-amber-200 bg-amber-50 p-2"
                                onClick={(event) => event.stopPropagation()}
                              >
                                <div className="text-xs font-medium text-amber-800">
                                  Rationale for {TRIAGE_STATUSES.find((entry) => entry.value === pendingTriageFor.status)?.label}:
                                </div>
                                <input
                                  type="text"
                                  value={triageRationale}
                                  onChange={(event) => setTriageRationale(event.target.value)}
                                  placeholder="Why is this the right decision?"
                                  className="h-8 w-full rounded border bg-background px-2 text-sm"
                                  autoFocus
                                  onKeyDown={(event) => {
                                    if (event.key === 'Enter' && triageRationale.trim()) confirmTriage(threat.id, pendingTriageFor.status)
                                  }}
                                />
                                <div className="flex items-center gap-2">
                                  <Button
                                    size="sm"
                                    className="h-7 text-xs"
                                    disabled={!triageRationale.trim()}
                                    onClick={() => confirmTriage(threat.id, pendingTriageFor.status)}
                                  >
                                    Confirm
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    className="h-7 text-xs"
                                    onClick={() => {
                                      setPendingTriageFor(null)
                                      setTriageRationale('')
                                    }}
                                  >
                                    Cancel
                                  </Button>
                                </div>
                              </div>
                            )}

                            {isSelected && (
                              <div className="ml-4 mt-1 rounded-md border border-slate-200 bg-slate-50 p-2">
                                <ThreatDetailPanel key={threat.id} threatModelId={threatModelId} threat={threat} personas={personas} />
                              </div>
                            )}
                          </div>
                        )
                      }}
                    />
                  </div>
                )}

                {selection && activeThreats.length === 0 && triagedThreats.length === 0 && (
                  <div className="py-8 text-center text-muted-foreground">
                    <p className="text-sm">No threats here yet.</p>
                  </div>
                )}

                {selection && activeThreats.length === 0 && triagedThreats.length > 0 && (
                  <div className="py-8 text-center text-muted-foreground">
                    <p className="text-sm">All threats have been triaged.</p>
                    <p className="mt-1 text-xs">Reopen from the section below if needed.</p>
                  </div>
                )}

                {selection && triagedThreats.length > 0 && (
                  <div className="mt-4 border-t pt-3">
                    <button
                      className="flex w-full items-center justify-between px-2 py-1 text-sm text-muted-foreground hover:text-foreground"
                      onClick={() => setShowTriagedThreats((open) => !open)}
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
                        {triagedThreats.map((threat) => {
                          const statusLabel =
                            TRIAGE_STATUSES.find((entry) => entry.value === threat.triageStatus)?.label || threat.triageStatus
                          return (
                            <div key={threat.id} className="group flex items-center justify-between gap-2 rounded-md px-2 py-2 hover:bg-slate-50">
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2">
                                  <NumberBadge number={threat.displayNumber} />
                                  <span className="truncate text-sm text-muted-foreground line-through">{threat.threatName}</span>
                                  <Badge variant="outline" className={cn('text-[10px]', TRIAGE_STATUS_COLORS[threat.triageStatus])}>
                                    {statusLabel}
                                  </Badge>
                                </div>
                                {threat.decisionRationale && (
                                  <p className="mt-0.5 truncate text-xs italic text-muted-foreground">{threat.decisionRationale}</p>
                                )}
                                <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={1} size="sm" />
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs text-blue-600 hover:bg-blue-50 hover:text-blue-700"
                                onClick={() => onUpdateTriageStatus(threat.id, 'open')}
                              >
                                Reopen
                              </Button>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
        </ResizablePanel>

        <ResizableHandle withHandle />

        {/* Column 3: the countermeasures of the selected scenario */}
        <ResizablePanel defaultSize="42%" minSize="20%">
          <div className="flex h-full flex-col">
            <div className="flex items-center justify-between border-b px-4 py-2">
              <div className="min-w-0">
                <div className="font-medium">Countermeasures</div>
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
                {selectedThreat && <ThreatStatusBadge status={deriveThreatStatus(selectedThreat.countermeasures)} />}
                {selectedThreat && (
                  <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={onAddCustomCountermeasure}>
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                )}
              </div>
            </div>

            {selectedThreat && (
              <div className="flex items-center gap-4 border-b px-4 py-2 text-xs">
                <div className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">Platform</span>
                  <Lock className="h-3 w-3 text-muted-foreground" />
                </div>
                <span className="text-muted-foreground/40">|</span>
                <div className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  <span className="text-muted-foreground">Gap</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-yellow-500" />
                  <span className="text-muted-foreground">Planned</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">Verified</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  <span className="text-muted-foreground">Waived</span>
                </div>
              </div>
            )}

            <ScrollArea className="flex-1">
              <div className="space-y-3 p-4">
                {selectedThreat && sortedCountermeasures.length > 0 && (
                  <SortableList
                    items={sortedCountermeasures}
                    getItemId={(countermeasure) => countermeasure.id}
                    onReorder={(reordered) => {
                      if (onReorderCountermeasures) onReorderCountermeasures(selectedThreat.id, reordered)
                    }}
                    renderItem={(countermeasure, dragHandleRef) => (
                      <CountermeasureCard
                        threatModelId={threatModelId}
                        threat={selectedThreat}
                        countermeasure={countermeasure}
                        dragHandleRef={dragHandleRef}
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
                        onSelectThreat={selectThreatByBackendId}
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
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>

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

      {editingTaxonomyFor && (
        <EditTaxonomyMappingsDialog
          open
          onOpenChange={(open) => {
            if (!open) setEditingTaxonomyFor(null)
          }}
          threatId={editingTaxonomyFor.backendId}
          threatName={editingTaxonomyFor.name}
          libraryTaxonomyEntries={editingTaxonomyFor.libraryEntries}
        />
      )}

      {editingTargetsFor && (
        <EditTargetsDialog
          open
          onOpenChange={(open) => {
            if (!open) setEditingTargetsFor(null)
          }}
          threatModelId={threatModelId}
          title={`${editingTargetsFor.displayNumber} Edit targets`}
          initialTargets={editingTargetsFor.targets.map((target) => ({ type: target.type, id: target.id }))}
          initialWholeSystem={editingTargetsFor.wholeSystem}
          mode="threat"
          isSaving={setThreatTargetsMutation.isPending}
          onSave={handleSaveTargets}
          onDelete={() =>
            setDeleteThreatConfirmFor({
              backendId: editingTargetsFor.backendThreatId,
              name: editingTargetsFor.threatName || 'this threat',
            })
          }
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

      <AlertDialog
        open={!!deleteThreatConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteThreatConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete threat?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes "{deleteThreatConfirmFor?.name}" from every target it sits on. Untouched generated controls linked
              only to it go too. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteThreatMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDeleteThreat()
              }}
              disabled={deleteThreatMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteThreatMutation.isPending ? (
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

      <Dialog
        open={!!editingThreatFor}
        onOpenChange={(open) => {
          if (!open) setEditingThreatFor(null)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit threat</DialogTitle>
            <DialogDescription>Update the threat name and description.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="edit-threat-name">Threat name *</Label>
              <Input
                id="edit-threat-name"
                value={editThreatName}
                onChange={(event) => setEditThreatName(event.target.value)}
                placeholder="Threat name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-threat-description">Description</Label>
              <Textarea
                id="edit-threat-description"
                value={editThreatDescription}
                onChange={(event) => setEditThreatDescription(event.target.value)}
                placeholder="Describe the threat"
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingThreatFor(null)}>
              Cancel
            </Button>
            <Button onClick={handleSaveEditThreat} disabled={!editThreatName.trim() || updateThreatMutation.isPending}>
              {updateThreatMutation.isPending ? (
                <>
                  <Loader2 className="mr-1 h-3 w-3 animate-spin" /> Saving
                </>
              ) : (
                'Save'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
