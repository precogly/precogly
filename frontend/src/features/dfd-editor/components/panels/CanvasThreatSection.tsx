/**
 * The Threats section of a node, flow, zone or boundary panel in the diagram
 * editor. Active threats are cards; each opens the threat modal (the same one
 * as the threat analysis screen). Triaged threats sit collapsed under them,
 * so they can be reopened. A card's countermeasure controls follow the
 * workspace rules: Planned asks for an owner first, Waived for a reason.
 */

import { useState, type SyntheticEvent } from 'react'
import { toast } from 'sonner'
import { ChevronDown, ChevronRight, Plus, Pencil, ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import {
  parseCountermeasureId,
  useThreatModelThreats,
  useUpdateCountermeasure,
  useUpdateTriageStatus,
  type UpdateCountermeasureInput,
} from '@/features/threat-models/api/threats'
import { writeErrorMessage } from '@/features/threat-models/lib/write-error-message'
import { AddThreatDialog } from '../threat-analysis/AddThreatDialog'
import { AddCountermeasureDialog } from '../threat-analysis/AddCountermeasureDialog'
import { ThreatEditor } from '../threat-analysis/ThreatEditor'
import { UserSearchCombobox } from '../threat-analysis/UserSearchCombobox'
import { WaiverReasonInput } from '../threat-analysis/WaiverReasonInput'
import { countermeasureStatusAction, countermeasureStatusOptions } from '../threat-analysis/countermeasure-utils'
import { canvasThreats, openCanvasThreat } from '../../lib/canvas-threats'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import {
  COUNTERMEASURE_STATUS_CONFIG,
  deriveThreatStatus,
  THREAT_STATUS_CONFIG,
} from '../../types/threat-analysis'
import { RatingBadge } from '@/features/threat-models/components/rating'
import type { AnalysisCountermeasure, AnalysisThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { TRIAGE_STATUS_COLORS, TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import { CONTROL_FUNCTIONS, CONTROL_NATURES } from '@/types/controls'

interface CanvasThreatSectionProps {
  threatModelId: string | undefined
  canvasId: string
  targetType: 'component' | 'flow' | 'zone' | 'boundary'
  targetName: string
  backendId: number | undefined
}

/** A status change waiting on its prompt: an owner for Planned, a reason for Waived. */
type StatusPrompt = { kind: 'assign-owner' | 'waive'; countermeasureId: number; name: string; owner: string }

export function CanvasThreatSection({
  threatModelId,
  canvasId,
  targetType,
  targetName,
  backendId,
}: CanvasThreatSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [showTriaged, setShowTriaged] = useState(false)
  const [showAddDialog, setShowAddDialog] = useState(false)
  /** The threat whose modal is open, by id: each render shows the fresh row from the query. */
  const [openThreatId, setOpenThreatId] = useState<string | null>(null)
  const [countermeasureThreat, setCountermeasureThreat] = useState<AnalysisThreat | null>(null)
  const [statusPrompt, setStatusPrompt] = useState<StatusPrompt | null>(null)
  const [editingCountermeasure, setEditingCountermeasure] = useState<{
    id: number
    name: string
    controlFunctions: string[]
    controlNature: string
  } | null>(null)
  const [editName, setEditName] = useState('')
  const [editControlFunctions, setEditControlFunctions] = useState<string[]>([])
  const [editControlNature, setEditControlNature] = useState('')
  const { isSecurityTeam } = useWorkspace()
  const updateCountermeasure = useUpdateCountermeasure()
  const updateTriageStatus = useUpdateTriageStatus()

  const openCountermeasureEditor = (id: number, name: string, controlFunctions?: string[], controlNature?: string) => {
    setEditingCountermeasure({ id, name, controlFunctions: controlFunctions || [], controlNature: controlNature || '' })
    setEditName(name)
    setEditControlFunctions(controlFunctions || [])
    setEditControlNature(controlNature || '')
  }

  const saveCountermeasure = () => {
    if (!editingCountermeasure || !editName.trim()) return
    updateCountermeasure.mutate(
      {
        countermeasureId: editingCountermeasure.id,
        data: { countermeasureName: editName.trim(), controlFunctions: editControlFunctions, controlNature: editControlNature },
      },
      {
        onSuccess: () => {
          setEditingCountermeasure(null)
        },
        onError: (error) => toast.error(writeErrorMessage(error, 'Could not save the countermeasure')),
      },
    )
  }

  const saveStatus = (countermeasureId: number, data: UpdateCountermeasureInput) => {
    updateCountermeasure.mutate(
      { countermeasureId, data },
      { onError: (error) => toast.error(writeErrorMessage(error, 'Could not change the status')) },
    )
  }

  /** Planned without an owner and Waived go through a prompt first, as in the workspace. */
  const handleStatusPick = (countermeasure: AnalysisCountermeasure, countermeasureId: number, status: CountermeasureStatus) => {
    if (status === countermeasure.status) return
    const action = countermeasureStatusAction(status, !!countermeasure.owner)
    if (action === 'change') {
      saveStatus(countermeasureId, { status })
      return
    }
    setStatusPrompt({
      kind: action,
      countermeasureId,
      name: countermeasure.countermeasureName || countermeasure.countermeasureId,
      owner: countermeasure.owner || '',
    })
  }

  const { data: threatData } = useThreatModelThreats(threatModelId)

  const threats = canvasThreats(threatData?.analysisThreats, canvasId)
  const openThreat = openCanvasThreat(threats, openThreatId)
  const threatCount = threats.active.length

  const handleUpdateTriageStatus = (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => {
    const threat = openCanvasThreat(threats, threatUiId)
    if (!threat) return
    updateTriageStatus.mutate(
      { threatId: threat.backendThreatId, triageStatus, decisionRationale },
      { onError: (error) => toast.error(writeErrorMessage(error, 'Could not change the triage status')) }
    )
  }

  /** The countermeasure controls sit inside the card; their clicks must not open the threat. */
  const stopCardClick = (event: SyntheticEvent) => event.stopPropagation()

  return (
    <div className="space-y-2">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between w-full text-sm font-medium hover:text-foreground text-muted-foreground"
      >
        <div className="flex items-center gap-2">
          {isOpen ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
          <ShieldAlert className="h-4 w-4" />
          <span>Threats</span>
          {threatCount > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-xs">
              {threatCount}
            </Badge>
          )}
        </div>
      </button>

      {isOpen && (
        <div className="space-y-2 pl-6">
          {backendId === undefined ? (
            <p className="text-xs text-muted-foreground">
              Save the diagram to enable threat management.
            </p>
          ) : (
            <>
              {threats.active.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  {threats.triaged.length > 0 ? 'Every threat here has been triaged.' : 'No threats added yet.'}
                </p>
              ) : (
                <div className="space-y-1.5">
                  {threats.active.map((threat) => {
                    const status = deriveThreatStatus(threat.countermeasures)
                    const statusConfig = THREAT_STATUS_CONFIG[status]

                    return (
                      <div
                        key={threat.id}
                        role="button"
                        tabIndex={0}
                        aria-label={`Open ${threat.displayNumber} ${threat.threatName || 'Unnamed threat'}`}
                        data-testid="canvas-threat-card"
                        data-threat-number={threat.displayNumber}
                        className="flex flex-col gap-1.5 p-2 rounded-md border bg-card text-sm cursor-pointer hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                        onClick={() => setOpenThreatId(threat.id)}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            setOpenThreatId(threat.id)
                          }
                        }}
                      >
                        <span className="text-sm font-medium leading-snug">
                          <span className="mr-1.5 inline-flex rounded border border-slate-300 bg-slate-50 px-1 font-mono text-[10px] text-slate-700">
                            {threat.displayNumber}
                          </span>
                          {threat.threatName || 'Unnamed threat'}
                        </span>
                        {threat.threatDescription && (
                          <p className="text-xs text-muted-foreground leading-snug line-clamp-2">
                            {threat.threatDescription}
                          </p>
                        )}
                        <div className="flex flex-wrap items-center gap-1">
                          <RatingBadge rating={threat.rating} size="sm" />
                          <Badge
                            variant="secondary"
                            className={cn('text-xs', statusConfig.bgColor)}
                          >
                            {statusConfig.label}
                          </Badge>
                        </div>
                        {threat.taxonomyEntries && threat.taxonomyEntries.length > 0 && (
                          <TaxonomyBadges
                            entries={threat.taxonomyEntries}
                            maxVisible={3}
                            size="sm"
                          />
                        )}
                        <div className="space-y-1 border-t pt-1.5" onClick={stopCardClick} onKeyDown={stopCardClick}>
                          <div className="flex items-center justify-between text-xs text-muted-foreground">
                            <span>Countermeasures ({threat.countermeasures.length})</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 gap-1 px-1.5 text-xs"
                              onClick={() => setCountermeasureThreat(threat)}
                            >
                              <Plus className="h-3 w-3" /> Add
                            </Button>
                          </div>
                          {threat.countermeasures.map((countermeasure) => {
                            const parsed = parseCountermeasureId(countermeasure.id)
                            const countermeasureName = countermeasure.countermeasureName || countermeasure.countermeasureId
                            return (
                              <div key={countermeasure.id} className="flex items-center gap-1.5">
                                <span className="min-w-0 flex-1 truncate text-xs" title={countermeasureName}>
                                  {countermeasureName}
                                </span>
                                {parsed.type === 'backend' && parsed.id !== null ? (
                                  <Select
                                    value={countermeasure.status}
                                    onValueChange={(status) => handleStatusPick(countermeasure, parsed.id!, status as CountermeasureStatus)}
                                  >
                                    <SelectTrigger
                                      className="h-6 w-[104px] text-[11px]"
                                      aria-label={`Status of ${countermeasureName}`}
                                    >
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      {countermeasureStatusOptions({ current: countermeasure.status, isSecurityTeam }).map((status) => (
                                        <SelectItem key={status} value={status} className="text-xs">
                                          {COUNTERMEASURE_STATUS_CONFIG[status].label}
                                        </SelectItem>
                                      ))}
                                    </SelectContent>
                                  </Select>
                                ) : (
                                  <span className="text-[11px] text-muted-foreground">
                                    {COUNTERMEASURE_STATUS_CONFIG[countermeasure.status]?.label ?? countermeasure.status}
                                  </span>
                                )}
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6"
                                  aria-label={`Edit ${countermeasure.countermeasureName || 'countermeasure'}`}
                                  onClick={() => openCountermeasureEditor(parsed.id!, countermeasureName, countermeasure.controlFunctions, countermeasure.controlNature)}
                                  disabled={parsed.type !== 'backend' || parsed.id === null}
                                >
                                  <Pencil className="h-3 w-3" />
                                </Button>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              {threats.triaged.length > 0 && (
                <div className="space-y-1">
                  <button
                    type="button"
                    className="flex w-full items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => setShowTriaged((open) => !open)}
                    aria-expanded={showTriaged}
                    data-testid="canvas-triaged-toggle"
                  >
                    {showTriaged ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                    <span>
                      {threats.triaged.length} triaged
                    </span>
                  </button>
                  {showTriaged &&
                    threats.triaged.map((threat) => {
                      const triageLabel =
                        TRIAGE_STATUSES.find((entry) => entry.value === threat.triageStatus)?.label || threat.triageStatus
                      return (
                        <button
                          key={threat.id}
                          type="button"
                          className="flex w-full items-center gap-1.5 rounded-md border px-2 py-1 text-left text-xs hover:bg-muted/50"
                          aria-label={`Open ${threat.displayNumber} ${threat.threatName || 'Unnamed threat'}`}
                          data-testid="canvas-triaged-threat"
                          data-threat-number={threat.displayNumber}
                          onClick={() => setOpenThreatId(threat.id)}
                        >
                          <span className="inline-flex rounded border border-slate-300 bg-slate-50 px-1 font-mono text-[10px] text-slate-700">
                            {threat.displayNumber}
                          </span>
                          <span className="min-w-0 flex-1 truncate line-through text-muted-foreground">
                            {threat.threatName || 'Unnamed threat'}
                          </span>
                          <Badge variant="outline" className={cn('shrink-0 text-[10px]', TRIAGE_STATUS_COLORS[threat.triageStatus])}>
                            {triageLabel}
                          </Badge>
                        </button>
                      )
                    })}
                </div>
              )}

              <Button
                variant="outline"
                size="sm"
                className="w-full gap-1"
                onClick={() => setShowAddDialog(true)}
              >
                <Plus className="h-3 w-3" />
                Add Threat
              </Button>

              <AddThreatDialog
                open={showAddDialog}
                onOpenChange={setShowAddDialog}
                initialTargets={[{ type: targetType, id: backendId }]}
                targetName={targetName}
                threatModelId={threatModelId}
              />
              {threatModelId !== undefined && (
                <ThreatEditor
                  threatModelId={threatModelId}
                  threat={openThreat}
                  onClose={() => setOpenThreatId(null)}
                  onUpdateTriageStatus={handleUpdateTriageStatus}
                  onDeleted={() => setOpenThreatId(null)}
                />
              )}
              {countermeasureThreat?.backendThreatId !== undefined && (
                <AddCountermeasureDialog
                  open={countermeasureThreat !== null}
                  onOpenChange={(open) => { if (!open) setCountermeasureThreat(null) }}
                  threatId={countermeasureThreat.backendThreatId}
                  threatName={countermeasureThreat.threatName || 'Unnamed threat'}
                  threatLibraryId={countermeasureThreat.threatLibraryId}
                  threatModelId={threatModelId}
                />
              )}
              <Dialog open={statusPrompt !== null} onOpenChange={(open) => { if (!open) setStatusPrompt(null) }}>
                <DialogContent className="sm:max-w-[425px]" data-testid="canvas-status-prompt">
                  {statusPrompt?.kind === 'assign-owner' ? (
                    <>
                      <DialogHeader>
                        <DialogTitle>Assign an owner</DialogTitle>
                        <DialogDescription>
                          A planned countermeasure needs an owner. Pick one for "{statusPrompt.name}".
                        </DialogDescription>
                      </DialogHeader>
                      <UserSearchCombobox
                        value={statusPrompt.owner}
                        onSelect={(assignee) => {
                          saveStatus(statusPrompt.countermeasureId, { assignedOwner: assignee.userId, status: 'planned' })
                          setStatusPrompt(null)
                        }}
                        onCancel={() => setStatusPrompt(null)}
                      />
                    </>
                  ) : statusPrompt?.kind === 'waive' ? (
                    <>
                      <DialogHeader>
                        <DialogTitle>Waive countermeasure</DialogTitle>
                        <DialogDescription>"{statusPrompt.name}" stays listed, with the reason.</DialogDescription>
                      </DialogHeader>
                      <WaiverReasonInput
                        onSubmit={(reason) => {
                          saveStatus(statusPrompt.countermeasureId, { status: 'waived', waiverReason: reason })
                          setStatusPrompt(null)
                        }}
                        onCancel={() => setStatusPrompt(null)}
                      />
                    </>
                  ) : null}
                </DialogContent>
              </Dialog>
              <Dialog open={editingCountermeasure !== null} onOpenChange={(open) => { if (!open) setEditingCountermeasure(null) }}>
                <DialogContent className="sm:max-w-[425px]">
                  <DialogHeader>
                    <DialogTitle>Edit Countermeasure</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="dfd-countermeasure-name">Name</Label>
                      <Input
                        id="dfd-countermeasure-name"
                        value={editName}
                        onChange={(event) => setEditName(event.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Control Functions</Label>
                      <div className="flex flex-wrap gap-3">
                        {CONTROL_FUNCTIONS.map((fn) => (
                          <label key={fn.value} className="flex items-center gap-1.5 text-sm">
                            <Checkbox
                              checked={editControlFunctions.includes(fn.value)}
                              onCheckedChange={(checked) => {
                                setEditControlFunctions((prev) =>
                                  checked
                                    ? [...prev, fn.value]
                                    : prev.filter((v) => v !== fn.value)
                                )
                              }}
                            />
                            {fn.label}
                          </label>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="dfd-countermeasure-nature">Control Nature</Label>
                      <Select value={editControlNature} onValueChange={setEditControlNature}>
                        <SelectTrigger id="dfd-countermeasure-nature"><SelectValue placeholder="Select nature..." /></SelectTrigger>
                        <SelectContent>
                          {CONTROL_NATURES.map((nature) => <SelectItem key={nature.value} value={nature.value}>{nature.label}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setEditingCountermeasure(null)}>Cancel</Button>
                    <Button onClick={saveCountermeasure} disabled={!editName.trim() || updateCountermeasure.isPending}>Save</Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      )}
    </div>
  )
}
