import { useState } from 'react'
import { ChevronDown, ChevronRight, Plus, Pencil, ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { useThreatModelThreats } from '@/features/threat-models/api/threats'
import { AddThreatDialog } from '../threat-analysis/AddThreatDialog'
import { AddCountermeasureDialog } from '../threat-analysis/AddCountermeasureDialog'
import { useUpdateCountermeasure } from '@/features/threat-models/api/threats'
import { parseCountermeasureId } from '@/features/threat-models/api/threats'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import {
  deriveThreatStatus,
  THREAT_STATUS_CONFIG,
  threatTargetsCanvasId,
} from '../../types/threat-analysis'
import { RatingBadge } from '@/features/threat-models/components/rating'
import type { AnalysisThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import { CONTROL_FUNCTIONS, CONTROL_NATURES } from '@/types/controls'

interface CanvasThreatSectionProps {
  threatModelId: string | undefined
  canvasId: string
  targetType: 'component' | 'flow' | 'zone' | 'boundary'
  targetName: string
  backendId: number | undefined
}

export function CanvasThreatSection({
  threatModelId,
  canvasId,
  targetType,
  targetName,
  backendId,
}: CanvasThreatSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [countermeasureThreat, setCountermeasureThreat] = useState<AnalysisThreat | null>(null)
  const [editingCountermeasure, setEditingCountermeasure] = useState<{
    id: number
    name: string
    controlFunctions: string[]
    controlNature: string
  } | null>(null)
  const [editName, setEditName] = useState('')
  const [editControlFunctions, setEditControlFunctions] = useState<string[]>([])
  const [editControlNature, setEditControlNature] = useState('')
  const updateCountermeasure = useUpdateCountermeasure()

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
      },
    )
  }

  const { data: threatData } = useThreatModelThreats(threatModelId)

  const threats: AnalysisThreat[] = threatData?.analysisThreats
    ? threatData.analysisThreats.filter(
        (t) => threatTargetsCanvasId(t, canvasId) && isActiveThreat(t.triageStatus)
      )
    : []

  const threatCount = threats.length

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
              {threats.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No threats added yet.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {threats.map((threat) => {
                    const status = deriveThreatStatus(threat.countermeasures)
                    const statusConfig = THREAT_STATUS_CONFIG[status]

                    return (
                      <div
                        key={threat.id}
                        className="flex flex-col gap-1.5 p-2 rounded-md border bg-card text-sm"
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
                        <div className="space-y-1 border-t pt-1.5">
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
                            return (
                              <div key={countermeasure.id} className="flex items-center gap-1.5">
                                <span className="min-w-0 flex-1 truncate text-xs" title={countermeasure.countermeasureName}>
                                  {countermeasure.countermeasureName || countermeasure.countermeasureId}
                                </span>
                                {parsed.type === 'backend' && parsed.id !== null ? (
                                  <Select
                                    value={countermeasure.status}
                                    onValueChange={(status) => {
                                      updateCountermeasure.mutate(
                                        { countermeasureId: parsed.id!, data: { status: status as CountermeasureStatus } },
                                      )
                                    }}
                                  >
                                    <SelectTrigger className="h-6 w-[92px] text-[11px]">
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      {(['gap', 'planned', 'verified', 'waived'] as CountermeasureStatus[]).map((status) => (
                                        <SelectItem key={status} value={status} className="text-xs">
                                          {status}
                                        </SelectItem>
                                      ))}
                                    </SelectContent>
                                  </Select>
                                ) : (
                                  <span className="text-[11px] capitalize text-muted-foreground">{countermeasure.status}</span>
                                )}
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6"
                                  aria-label={`Edit ${countermeasure.countermeasureName || 'countermeasure'}`}
                                  onClick={() => openCountermeasureEditor(parsed.id!, countermeasure.countermeasureName || countermeasure.countermeasureId, countermeasure.controlFunctions, countermeasure.controlNature)}
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
              {countermeasureThreat?.backendThreatId !== undefined && (
                <AddCountermeasureDialog
                  open={countermeasureThreat !== null}
                  onOpenChange={(open) => { if (!open) setCountermeasureThreat(null) }}
                  threatId={countermeasureThreat.backendThreatId}
                  threatName={countermeasureThreat.threatName || 'Unnamed threat'}
                  threatLibraryId={countermeasureThreat.threatId.startsWith('lib-') ? Number(countermeasureThreat.threatId.slice(4)) : null}
                  threatModelId={threatModelId}
                />
              )}
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
