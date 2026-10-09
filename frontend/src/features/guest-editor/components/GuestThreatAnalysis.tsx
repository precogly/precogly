import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowLeft,
  Cog,
  Database,
  User,
  Building2,
  ArrowRight,
  Box,
  Plus,
  Trash2,
  Pencil,
  Shield,
  ShieldCheck,
  AlertTriangle,
  Info,
  Globe,
  List,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from '@/components/ui/resizable'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GuestThreatDialog } from './GuestAddThreatDialog'
import { GuestCountermeasureDialog } from './GuestCountermeasureDialog'
import type { GuestThreat, GuestCountermeasure, GuestTargetRef, ControlFunction, ControlNature } from '../types'
import {
  LEVEL_COLORS,
  STATUS_COLORS,
  getThreatWarning,
  GUEST_THREAT_STATUS_OPTIONS,
  threatDisplayNumber,
  countermeasureDisplayNumber,
} from '../types'
import { STRIDE_CONFIG } from '@/types/domain'
import { targetLabel } from '../lib/guest-model'
import { hiddenTargetsNote, targetOptions } from '../lib/guest-targets'

const CONTROL_FUNCTION_COLORS: Record<ControlFunction, string> = {
  preventive: 'bg-green-100 text-green-800',
  detective: 'bg-blue-100 text-blue-800',
  corrective: 'bg-orange-100 text-orange-800',
  deterrent: 'bg-purple-100 text-purple-800',
  recovery: 'bg-teal-100 text-teal-800',
  compensating: 'bg-amber-100 text-amber-800',
}

const CONTROL_NATURE_COLORS: Record<ControlNature | '', string> = {
  '': 'bg-muted text-muted-foreground',
  technical: 'bg-sky-100 text-sky-800',
  administrative: 'bg-rose-100 text-rose-800',
  physical: 'bg-stone-100 text-stone-800',
}

const CONTROL_NATURE_LABELS: Record<ControlNature | '', string> = {
  '': 'Nature not set',
  technical: 'Technical',
  administrative: 'Admin/Procedural',
  physical: 'Physical',
}

const GROUP_ICONS: Record<string, typeof Cog> = {
  process: Cog,
  datastore: Database,
  humanActor: User,
  systemActor: Building2,
  systemScope: Box,
  flow: ArrowRight,
  zone: Shield,
  boundary: ShieldCheck,
}

const GROUP_LABELS: Record<string, string> = {
  process: 'Processes',
  datastore: 'Data Stores',
  humanActor: 'Human Actors',
  systemActor: 'System Actors',
  systemScope: 'System Scope',
  flow: 'Flows',
  zone: 'Zones',
  boundary: 'Boundaries',
}

const GROUP_ORDER = ['process', 'datastore', 'humanActor', 'systemActor', 'systemScope', 'flow', 'zone', 'boundary']

type ThreatSortField = 'number' | 'status' | 'level' | 'name'

const SORT_OPTIONS: { value: ThreatSortField; label: string }[] = [
  { value: 'number', label: 'Number' },
  { value: 'status', label: 'Status' },
  { value: 'level', label: 'Level' },
  { value: 'name', label: 'Name' },
]

const STATUS_SORT_ORDER: Record<string, number> = {
  open: 0, mitigate: 1, accept: 2, delegate: 3, eliminate: 4,
}

const LEVEL_SORT_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

/** What the left column lists: a diagram element, the whole system, or every threat. */
type Selection =
  | { kind: 'all' }
  | { kind: 'wholeSystem' }
  | { kind: 'element'; target: GuestTargetRef; label: string }

export function GuestThreatAnalysis() {
  const navigate = useNavigate()
  const guestEditor = useGuestEditor()

  const [selection, setSelection] = useState<Selection>({ kind: 'all' })
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null)
  const [sortField, setSortField] = useState<ThreatSortField>('number')

  const [showThreatDialog, setShowThreatDialog] = useState(false)
  const [editingThreat, setEditingThreat] = useState<GuestThreat | undefined>(undefined)

  const [showCountermeasureDialog, setShowCountermeasureDialog] = useState(false)
  const [editingCountermeasure, setEditingCountermeasure] = useState<GuestCountermeasure | undefined>(undefined)

  const nodes = useMemo(() => guestEditor?.nodes ?? [], [guestEditor])
  const edges = useMemo(() => guestEditor?.edges ?? [], [guestEditor])
  const allThreats = useMemo(() => guestEditor?.getAllThreats() ?? [], [guestEditor])

  const groups = useMemo(() => {
    const byGroup = new Map<string, { target: GuestTargetRef; label: string }[]>()
    for (const option of targetOptions(nodes, edges)) {
      const node = option.ref.type === 'component' || option.ref.type === 'zone' ? nodes.find((candidate) => candidate.id === option.ref.id) : undefined
      const group = option.ref.type === 'component' ? (node?.type ?? 'process') : option.ref.type
      const list = byGroup.get(group) ?? []
      list.push({ target: option.ref, label: option.label })
      byGroup.set(group, list)
    }
    return GROUP_ORDER.filter((group) => byGroup.has(group)).map((group) => [group, byGroup.get(group)!] as const)
  }, [nodes, edges])

  const threatsForSelection = useMemo(() => {
    if (!guestEditor) return []
    if (selection.kind === 'all') return allThreats
    if (selection.kind === 'wholeSystem') return guestEditor.getWholeSystemThreats()
    return guestEditor.getThreatsForTarget(selection.target.id)
  }, [guestEditor, selection, allThreats])

  const sortedThreats = useMemo(() => {
    const sorted = [...threatsForSelection]
    sorted.sort((a, b) => {
      switch (sortField) {
        case 'number':
          return a.number - b.number
        case 'status':
          return (STATUS_SORT_ORDER[a.status] ?? 99) - (STATUS_SORT_ORDER[b.status] ?? 99)
        case 'level':
          return (LEVEL_SORT_ORDER[a.level] ?? 99) - (LEVEL_SORT_ORDER[b.level] ?? 99)
        case 'name':
          return a.name.localeCompare(b.name)
      }
    })
    return sorted
  }, [threatsForSelection, sortField])

  if (!guestEditor) return null

  const selectedThreat = selectedThreatId ? allThreats.find((t) => t.id === selectedThreatId) ?? null : null
  const countermeasuresForThreat = selectedThreatId ? guestEditor.getCountermeasuresForThreat(selectedThreatId) : []
  const wholeSystemCount = guestEditor.getWholeSystemThreats().length

  const selectionLabel = selection.kind === 'all' ? 'All threats' : selection.kind === 'wholeSystem' ? 'Whole system' : selection.label

  const handleSelect = (next: Selection) => {
    setSelection(next)
    setSelectedThreatId(null)
  }

  const handleAddThreat = () => {
    setEditingThreat(undefined)
    setShowThreatDialog(true)
  }

  const handleEditThreat = (threat: GuestThreat) => {
    setEditingThreat(threat)
    setShowThreatDialog(true)
  }

  const handleDeleteThreat = (threatId: string) => {
    guestEditor.removeThreat(threatId)
    if (selectedThreatId === threatId) setSelectedThreatId(null)
  }

  const handleAddCountermeasure = () => {
    setEditingCountermeasure(undefined)
    setShowCountermeasureDialog(true)
  }

  const handleEditCountermeasure = (countermeasure: GuestCountermeasure) => {
    setEditingCountermeasure(countermeasure)
    setShowCountermeasureDialog(true)
  }

  const describeTargets = (threat: GuestThreat): string => {
    const parts: string[] = []
    if (threat.wholeSystem) parts.push('whole system')
    else if (threat.targets.length > 0) parts.push(threat.targets.map((target) => targetLabel(target, nodes, edges)).join(', '))
    const hidden = hiddenTargetsNote(threat.hiddenTargetRefs, threat.hiddenBlueprintTargetCount)
    if (hidden) parts.push(hidden)
    return parts.join('; ')
  }

  const describeScope = (countermeasure: GuestCountermeasure): string => {
    const parts: string[] = []
    if (countermeasure.targets.length === 0 && countermeasure.hiddenTargetRefs.length === 0) return 'whole system'
    if (countermeasure.targets.length > 0) parts.push(countermeasure.targets.map((target) => targetLabel(target, nodes, edges)).join(', '))
    if (countermeasure.hiddenTargetRefs.length > 0) {
      parts.push(`${countermeasure.hiddenTargetRefs.length} element${countermeasure.hiddenTargetRefs.length === 1 ? '' : 's'} not on the diagram`)
    }
    return parts.join('; ')
  }

  const listButtonClass = (active: boolean) =>
    cn(
      'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-sm text-left hover:bg-muted/50',
      active && 'bg-muted'
    )

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Subheader */}
      <div className="flex items-center gap-3 px-4 py-2 border-b bg-muted/30">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate('/guest')}
          className="gap-1.5"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Diagram
        </Button>
        <div className="h-4 w-px bg-border" />
        <h2 className="text-sm font-medium">Threat Analysis</h2>
      </div>

      {/* 3-column layout */}
      <div className="min-h-0 flex-1 overflow-hidden h-full">
        <ResizablePanelGroup orientation="horizontal">
          {/* Column 1: elements */}
          <ResizablePanel defaultSize="25%" minSize="15%" maxSize="35%">
            <div className="h-full flex flex-col border-r">
              <div className="px-3 py-2 border-b bg-muted/20">
                <h3 className="text-sm font-medium">Components</h3>
                <p className="text-xs text-muted-foreground">
                  {groups.reduce((sum, [, items]) => sum + items.length, 0)} elements, {allThreats.length} threat{allThreats.length !== 1 ? 's' : ''}
                </p>
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2 space-y-3">
                  <div className="space-y-0.5">
                    <button onClick={() => handleSelect({ kind: 'all' })} className={listButtonClass(selection.kind === 'all')} data-testid="guest-all-threats">
                      <span className="flex items-center gap-1.5 truncate"><List className="h-3.5 w-3.5 text-muted-foreground" />All threats</span>
                      {allThreats.length > 0 && <Badge variant="secondary" className="h-5 px-1.5 text-xs shrink-0">{allThreats.length}</Badge>}
                    </button>
                    <button onClick={() => handleSelect({ kind: 'wholeSystem' })} className={listButtonClass(selection.kind === 'wholeSystem')} data-testid="guest-whole-system">
                      <span className="flex items-center gap-1.5 truncate"><Globe className="h-3.5 w-3.5 text-muted-foreground" />Whole system</span>
                      {wholeSystemCount > 0 && <Badge variant="secondary" className="h-5 px-1.5 text-xs shrink-0">{wholeSystemCount}</Badge>}
                    </button>
                  </div>
                  {groups.map(([group, items]) => {
                    const Icon = GROUP_ICONS[group] || Cog
                    return (
                      <div key={group}>
                        <div className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          <Icon className="h-3 w-3" />
                          {GROUP_LABELS[group] || group}
                        </div>
                        <div className="space-y-0.5">
                          {items.map((item) => {
                            const threatCount = guestEditor.getThreatCount(item.target.id)
                            const active = selection.kind === 'element' && selection.target.id === item.target.id
                            return (
                              <button
                                key={item.target.id}
                                onClick={() => handleSelect({ kind: 'element', target: item.target, label: item.label })}
                                className={listButtonClass(active)}
                              >
                                <span className="truncate">{item.label}</span>
                                {threatCount > 0 && (
                                  <Badge variant="secondary" className="h-5 px-1.5 text-xs shrink-0">
                                    {threatCount}
                                  </Badge>
                                )}
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    )
                  })}

                  {groups.length === 0 && (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      No components in the diagram yet. Add components on the canvas first.
                    </p>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Column 2: threats for the selection */}
          <ResizablePanel defaultSize="35%" minSize="20%" maxSize="55%">
            <div className="h-full flex flex-col border-r">
              <div className="px-3 py-2 border-b bg-muted/20 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium">Threats: {selectionLabel}</h3>
                  <p className="text-xs text-muted-foreground">
                    {threatsForSelection.length} threat{threatsForSelection.length !== 1 ? 's' : ''}
                  </p>
                </div>
                <div className="flex items-center gap-1.5">
                  {threatsForSelection.length > 1 && (
                    <Select value={sortField} onValueChange={(v) => setSortField(v as ThreatSortField)}>
                      <SelectTrigger className="h-7 w-[120px] text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SORT_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            Sort: {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                  <Button size="sm" variant="outline" onClick={handleAddThreat} className="gap-1" data-testid="guest-add-threat">
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                </div>
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2">
                  {threatsForSelection.length === 0 ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      No threats here yet. Click &ldquo;Add&rdquo; to create one.
                    </p>
                  ) : (
                    <div className="space-y-1">
                      {sortedThreats.map((threat) => {
                        const countermeasureCount = guestEditor.getCountermeasureCount(threat.id)
                        const warning = getThreatWarning(threat, countermeasureCount)
                        return (
                          <div
                            key={threat.id}
                            role="button"
                            tabIndex={0}
                            onClick={() => setSelectedThreatId(threat.id)}
                            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedThreatId(threat.id) } }}
                            className={cn(
                              'w-full flex flex-col gap-1 p-2 rounded-md text-sm text-left hover:bg-muted/50 cursor-pointer group',
                              selectedThreatId === threat.id && 'bg-muted'
                            )}
                            data-testid="guest-threat-row"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <Badge variant="outline" className="shrink-0 font-mono text-xs">{threatDisplayNumber(threat)}</Badge>
                                <Badge
                                  variant="secondary"
                                  className={cn('shrink-0 text-xs capitalize', STATUS_COLORS[threat.status])}
                                >
                                  {threat.status}
                                </Badge>
                                <Badge
                                  variant="secondary"
                                  className={cn('shrink-0 text-xs capitalize', LEVEL_COLORS[threat.level])}
                                >
                                  {threat.level}
                                </Badge>
                                {threat.category && STRIDE_CONFIG[threat.category] && (
                                  <Badge
                                    variant="outline"
                                    className="shrink-0 text-xs border"
                                    style={{
                                      color: STRIDE_CONFIG[threat.category].color,
                                      borderColor: STRIDE_CONFIG[threat.category].color,
                                    }}
                                  >
                                    {STRIDE_CONFIG[threat.category].label}
                                  </Badge>
                                )}
                                <span className="truncate">{threat.name}</span>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                {warning && (
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                                    </TooltipTrigger>
                                    <TooltipContent side="top">
                                      <p className="text-xs">{warning}</p>
                                    </TooltipContent>
                                  </Tooltip>
                                )}
                                {countermeasureCount > 0 && (
                                  <Badge variant="outline" className="h-5 px-1.5 text-xs gap-0.5">
                                    <Shield className="h-2.5 w-2.5" />
                                    {countermeasureCount}
                                  </Badge>
                                )}
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100"
                                  aria-label={`Edit ${threatDisplayNumber(threat)}`}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    handleEditThreat(threat)
                                  }}
                                >
                                  <Pencil className="h-3 w-3" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100 text-muted-foreground hover:text-red-600"
                                  aria-label={`Delete ${threatDisplayNumber(threat)}`}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    handleDeleteThreat(threat.id)
                                  }}
                                >
                                  <Trash2 className="h-3 w-3" />
                                </Button>
                              </div>
                            </div>
                            <p className="text-xs text-muted-foreground pl-0.5">On: {describeTargets(threat) || 'nothing'}</p>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Column 3: countermeasures for the selected threat */}
          <ResizablePanel defaultSize="40%" minSize="20%">
            <div className="h-full flex flex-col">
              <div className="px-3 py-2 border-b bg-muted/20 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-medium">
                    {selectedThreat
                      ? `Countermeasures: ${threatDisplayNumber(selectedThreat)} ${selectedThreat.name}`
                      : 'Countermeasures'}
                  </h3>
                  {selectedThreat && (
                    <p className="text-xs text-muted-foreground">
                      {countermeasuresForThreat.length} countermeasure
                      {countermeasuresForThreat.length !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
                {selectedThreat && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAddCountermeasure}
                    className="gap-1"
                    data-testid="guest-add-countermeasure"
                  >
                    <Plus className="h-3 w-3" />
                    Add
                  </Button>
                )}
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2">
                  {selectedThreat && selectedThreat.status !== 'mitigate' && selectedThreat.status !== 'open' && (
                    <div className="flex items-start gap-2 p-2 mb-2 rounded-md bg-muted/50 border text-xs text-muted-foreground">
                      <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                      <span>
                        This threat&apos;s status is &ldquo;{GUEST_THREAT_STATUS_OPTIONS.find((o) => o.value === selectedThreat.status)?.label ?? selectedThreat.status}&rdquo;. Countermeasures are optional.
                      </span>
                    </div>
                  )}
                  {!selectedThreat ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      Select a threat to view its countermeasures.
                    </p>
                  ) : countermeasuresForThreat.length === 0 ? (
                    <p className="text-xs text-muted-foreground px-2 py-4 text-center">
                      No countermeasures yet. Click &ldquo;Add&rdquo; to create one.
                    </p>
                  ) : (
                    <div className="space-y-1">
                      {countermeasuresForThreat.map((countermeasure) => {
                        const otherThreats = countermeasure.threatIds
                          .filter((threatId) => threatId !== selectedThreat.id)
                          .map((threatId) => allThreats.find((candidate) => candidate.id === threatId))
                          .filter((candidate): candidate is GuestThreat => candidate !== undefined)
                        return (
                          <div
                            key={countermeasure.id}
                            className="flex flex-col gap-1 p-2 rounded-md border bg-card text-sm group"
                            data-testid="guest-countermeasure-row"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-start gap-2 min-w-0">
                                <Badge variant="outline" className="shrink-0 font-mono text-xs mt-0.5">{countermeasureDisplayNumber(countermeasure)}</Badge>
                                <div className="flex flex-wrap gap-1 shrink-0 pt-0.5">
                                  {countermeasure.controlFunction.map((fn) => (
                                    <Badge
                                      key={fn}
                                      variant="secondary"
                                      className={cn('text-xs capitalize', CONTROL_FUNCTION_COLORS[fn])}
                                    >
                                      {fn}
                                    </Badge>
                                  ))}
                                  <Badge
                                    variant="outline"
                                    className={cn('text-xs', CONTROL_NATURE_COLORS[countermeasure.controlNature])}
                                  >
                                    {CONTROL_NATURE_LABELS[countermeasure.controlNature]}
                                  </Badge>
                                </div>
                                <div className="min-w-0">
                                  <span className="truncate block">{countermeasure.name}</span>
                                  {countermeasure.description && (
                                    <span className="text-xs text-muted-foreground truncate block">
                                      {countermeasure.description}
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100"
                                  aria-label={`Edit ${countermeasureDisplayNumber(countermeasure)}`}
                                  onClick={() => handleEditCountermeasure(countermeasure)}
                                >
                                  <Pencil className="h-3 w-3" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 touch:opacity-100 text-muted-foreground hover:text-red-600"
                                  aria-label={`Delete ${countermeasureDisplayNumber(countermeasure)}`}
                                  onClick={() => guestEditor.removeCountermeasure(countermeasure.id)}
                                >
                                  <Trash2 className="h-3 w-3" />
                                </Button>
                              </div>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Applies to: {describeScope(countermeasure)}
                              {otherThreats.length > 0 && (
                                <>; also mitigates {otherThreats.map((threat) => threatDisplayNumber(threat)).join(', ')}</>
                              )}
                            </p>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Dialogs */}
      <GuestThreatDialog
        open={showThreatDialog}
        onOpenChange={setShowThreatDialog}
        initialTarget={selection.kind === 'element' ? selection.target : null}
        initialWholeSystem={selection.kind === 'wholeSystem'}
        targetName={selection.kind === 'element' ? selection.label : undefined}
        editThreat={editingThreat}
      />

      {selectedThreat && (
        <GuestCountermeasureDialog
          open={showCountermeasureDialog}
          onOpenChange={setShowCountermeasureDialog}
          initialThreatId={selectedThreat.id}
          editCountermeasure={editingCountermeasure}
        />
      )}
    </div>
  )
}
