/**
 * "Add threat" (plan 11.3 dialogs): a multi-target picker preset from the
 * selection with "whole system" allowed, a level select with `info`, a
 * business objectives picker once the model has one, and the actor. From
 * the library (ranked by the AI owl when one component is the target) or
 * written by hand.
 */

import { useEffect, useState } from 'react'
import { Plus, Search, FileText, Library, Info, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { RATING_LEVEL_CLASSES } from '@/features/threat-models/components/rating'
import { OwlMark } from '@/features/ai/components/OwlMark'
import { OwlToggle } from '@/features/ai/components/OwlToggle'
import { AiErrorState } from '@/features/ai/components/AiErrorState'
import { useAiAvailability, useSuggestThreats, type ThreatSuggestion } from '@/features/ai/api/suggest'
import {
  useThreatLibrary,
  useThreats,
  useCreateThreat,
  useCreateInstanceTaxonomyEntry,
  useThreatPersonas,
  type CreateThreatInput,
  type TargetRef,
} from '@/features/threat-models/api/threats'
import { useTaxonomyEntries } from '@/features/libraries/api/libraries'
import { TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import { formatTaxonomyEntryLabel } from '@/types/domain'
import { RATING_LEVELS, type RatingLevel } from '@/types/risk'
import { TargetPicker } from './TargetPicker'
import { BusinessObjectivesPicker } from './BusinessObjectivesPicker'
import { useHasBusinessObjectives } from './useHasBusinessObjectives'
import { ActorPicker } from './ActorPicker'
import { NO_ACTOR, type ActorValue } from './actor-utils'

interface AddThreatDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string | undefined
  /** Preselected from the tree; empty with `initialWholeSystem` for the System row. */
  initialTargets: TargetRef[]
  initialWholeSystem?: boolean
  /** The selection's name for the heading ("PLC", "System"). */
  targetName: string
  onSuccess?: () => void
}

export function AddThreatDialog({
  open,
  onOpenChange,
  threatModelId,
  initialTargets,
  initialWholeSystem = false,
  targetName,
  onSuccess,
}: AddThreatDialogProps) {
  const [activeTab, setActiveTab] = useState<'library' | 'custom'>('library')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(null)
  const [selectedLevel, setSelectedLevel] = useState<RatingLevel>('medium')

  // Shared by both tabs
  const [targets, setTargets] = useState<TargetRef[]>(initialTargets)
  const [wholeSystem, setWholeSystem] = useState(initialWholeSystem)
  const [objectiveIds, setObjectiveIds] = useState<number[]>([])
  const [actor, setActor] = useState<ActorValue>(NO_ACTOR)

  // Custom threat fields
  const [customName, setCustomName] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [customLevel, setCustomLevel] = useState<RatingLevel>('medium')
  const [customTriageStatus, setCustomTriageStatus] = useState<TriageStatus>('open')
  const [customTaxonomyEntryId, setCustomTaxonomyEntryId] = useState<string>('none')
  const [showAllThreats, setShowAllThreats] = useState(false)
  // Whether the list is the model's ranking rather than the raw library. The
  // ranker only ever ranks one component's own pool, so ranking and "show
  // all" are mutually exclusive by construction.
  const [showRanked, setShowRanked] = useState(false)

  // The library is scoped to a component when exactly one component is the
  // target; any other target mix shows the whole library.
  const singleComponentId = targets.length === 1 && targets[0].type === 'component' && !wholeSystem ? targets[0].id : null
  const effectiveComponentId = singleComponentId !== null && !showAllThreats ? singleComponentId : undefined

  const { data: threatLibrary, isLoading } = useThreatLibrary(effectiveComponentId, threatModelId)
  const createThreat = useCreateThreat()
  const createInstanceTaxonomyEntry = useCreateInstanceTaxonomyEntry()
  const { data: allTaxonomyEntries } = useTaxonomyEntries()
  const { data: personas = [] } = useThreatPersonas(threatModelId)
  const hasObjectives = useHasBusinessObjectives(threatModelId ?? '')

  const taxonomyEntriesByTaxonomy = allTaxonomyEntries
    ? Object.entries(
        allTaxonomyEntries.reduce<Record<string, typeof allTaxonomyEntries>>((acc, entry) => {
          const key = entry.taxonomyName ?? entry.taxonomySlug
          if (!acc[key]) acc[key] = []
          acc[key].push(entry)
          return acc
        }, {})
      )
    : []

  // Ranking is component-only: the suggest endpoint answers other targets with
  // an empty list, so the owl only shows for one component.
  const availability = useAiAvailability(singleComponentId)
  const aiAvailable = availability.data?.available ?? false
  const suggest = useSuggestThreats()

  // Threats the single target already carries come out of the list: the
  // backend rejects the duplicate. Triaged threats count as present.
  const singleTarget = targets.length === 1 && !wholeSystem ? targets[0] : null
  const existingThreats = useThreats(
    singleTarget ? { [singleTarget.type]: singleTarget.id } : {},
    { enabled: open && singleTarget !== null }
  )
  const alreadyAdded = new Set(
    singleTarget
      ? (existingThreats.data?.map((threat) => threat.threatLibrary).filter((id): id is number => id !== null) ?? [])
      : []
  )

  const matchesQuery = (name?: string | null, description?: string | null, taxonomy?: string[]) => {
    const query = searchQuery.toLowerCase()
    return (
      name?.toLowerCase().includes(query) ||
      description?.toLowerCase().includes(query) ||
      (taxonomy?.some((entry) => entry.toLowerCase().includes(query)) ?? false)
    )
  }

  const availableThreats = threatLibrary?.filter((threat) => !alreadyAdded.has(threat.id)) ?? []

  const filteredThreats = availableThreats.filter((threat) => {
    const query = searchQuery.toLowerCase()
    const taxonomyMatch =
      threat.taxonomyEntries?.some(
        (entry) => entry.title.toLowerCase().includes(query) || entry.externalId.toLowerCase().includes(query)
      ) ?? false
    return threat.name?.toLowerCase().includes(query) || threat.description?.toLowerCase().includes(query) || taxonomyMatch
  })

  const filteredSuggestions =
    suggest.data?.suggestions.filter((suggestion) =>
      matchesQuery(suggestion.threatName, suggestion.threatDescription, suggestion.taxonomy)
    ) ?? []

  const selectedThreatName = showRanked
    ? suggest.data?.suggestions.find((suggestion) => suggestion.threatLibrary === selectedThreatId)?.threatName
    : threatLibrary?.find((threat) => threat.id === selectedThreatId)?.name

  const handleShowAllChange = (next: boolean) => {
    setShowAllThreats(next)
    setSelectedThreatId(null)
    if (next) setShowRanked(false)
  }

  const handleRankedChange = (next: boolean) => {
    setShowRanked(next)
    setSelectedThreatId(null)
    if (next && singleComponentId !== null && !suggest.data && !suggest.isPending) {
      suggest.mutate({ targetId: singleComponentId })
    }
  }

  const targetsValid = wholeSystem || targets.length > 0

  const sharedInput = (): Omit<CreateThreatInput, 'threatModel'> => ({
    targets: wholeSystem ? [] : targets,
    wholeSystem,
    actorPersona: actor.actorPersona,
    threatActorText: actor.actorPersona !== null ? '' : actor.threatActorText,
    ...(hasObjectives && objectiveIds.length > 0 && { businessObjectiveIds: objectiveIds }),
  })

  const handleAddFromLibrary = () => {
    if (!selectedThreatId || !threatModelId || !targetsValid) return
    createThreat.mutate(
      {
        threatModel: threatModelId,
        ...sharedInput(),
        threatLibrary: selectedThreatId,
        ratingInputs: { level: selectedLevel },
      },
      {
        onSuccess: () => {
          onOpenChange(false)
          resetForm()
          onSuccess?.()
        },
      }
    )
  }

  const handleAddCustom = () => {
    if (!customName.trim() || !threatModelId || !targetsValid) return
    const taxonomyEntryIdNum = customTaxonomyEntryId !== 'none' ? Number(customTaxonomyEntryId) : null
    createThreat.mutate(
      {
        threatModel: threatModelId,
        ...sharedInput(),
        threatLibrary: null,
        threatName: customName,
        threatDescription: customDescription,
        ratingInputs: { level: customLevel },
        triageStatus: customTriageStatus,
        status: 'exposed',
      },
      {
        onSuccess: (created) => {
          if (taxonomyEntryIdNum) {
            createInstanceTaxonomyEntry.mutate({ taxonomyEntry: taxonomyEntryIdNum, threat: created.id })
          }
          onOpenChange(false)
          resetForm()
          onSuccess?.()
        },
      }
    )
  }

  const resetForm = () => {
    setSearchQuery('')
    setSelectedThreatId(null)
    setSelectedLevel('medium')
    setTargets(initialTargets)
    setWholeSystem(initialWholeSystem)
    setObjectiveIds([])
    setActor(NO_ACTOR)
    setCustomName('')
    setCustomDescription('')
    setCustomLevel('medium')
    setCustomTriageStatus('open')
    setCustomTaxonomyEntryId('none')
    setActiveTab('library')
    setShowAllThreats(false)
    setShowRanked(false)
    suggest.reset()
  }

  // The dialog is re-rendered in place with a new selection, so the fields
  // reset on open; resetting on close would blank them mid-fade.
  useEffect(() => {
    if (open) resetForm()
    // `resetForm` is redeclared every render; `open` is the real trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const isSubmitting = createThreat.isPending

  const levelSelect = (id: string, value: RatingLevel, onChange: (level: RatingLevel) => void) => (
    <Select value={value} onValueChange={(next) => onChange(next as RatingLevel)}>
      <SelectTrigger id={id}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {RATING_LEVELS.map((entry) => (
          <SelectItem key={entry.value} value={entry.value}>
            {entry.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  const appliesToSection = threatModelId && (
    <div className="space-y-2 rounded-md border p-3">
      <Label>Applies to</Label>
      <TargetPicker
        threatModelId={threatModelId}
        value={targets}
        onChange={setTargets}
        allowWholeSystem
        wholeSystem={wholeSystem}
        onWholeSystemChange={setWholeSystem}
        idPrefix="add-threat"
        emptyHint="Pick at least one target, or make it a whole-system threat."
      />
      <div className="grid grid-cols-2 gap-3 pt-1">
        {hasObjectives && (
          <div className="space-y-1">
            <Label className="text-xs">Business objectives</Label>
            <BusinessObjectivesPicker threatModelId={threatModelId} value={objectiveIds} onChange={setObjectiveIds} />
          </div>
        )}
        <div className="space-y-1">
          <Label className="text-xs">Actor</Label>
          <ActorPicker threatModelId={threatModelId} personas={personas} value={actor} onChange={setActor} compact />
        </div>
      </div>
    </div>
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Add threat</DialogTitle>
          <DialogDescription>
            Add a threat on <span className="font-medium">{targetName}</span>. Change the targets below if needed.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as 'library' | 'custom')}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="library">From library</TabsTrigger>
            <TabsTrigger value="custom">Custom threat</TabsTrigger>
          </TabsList>

          <TabsContent value="library" className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search threats"
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                className="pl-9"
              />
            </div>

            {singleComponentId !== null && (
              <div className="flex items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
                  {showRanked ? <OwlMark className="h-4 w-4 shrink-0" /> : <Library className="h-4 w-4 shrink-0" />}
                  <span className="truncate">
                    {showRanked
                      ? 'Ranked for this component'
                      : showAllThreats
                        ? 'Showing all threats'
                        : "Showing threats for this component's library"}
                  </span>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <OwlToggle
                    label="Rank"
                    tooltip={showRanked ? 'Show the unranked library' : 'Rank these threats by relevance'}
                    active={showRanked}
                    pending={suggest.isPending}
                    unavailable={!aiAvailable}
                    blockedReason={showAllThreats ? "Ranking covers this component's library only" : null}
                    onChange={handleRankedChange}
                  />
                  <Switch id="show-all-threats" checked={showAllThreats} onCheckedChange={handleShowAllChange} />
                  <Label htmlFor="show-all-threats" className="text-sm">
                    Show all
                  </Label>
                </div>
              </div>
            )}

            <ScrollArea className="h-[240px] rounded-md border">
              {showRanked ? (
                <RankedList
                  pending={suggest.isPending}
                  error={suggest.error}
                  suggestions={filteredSuggestions}
                  hasResults={suggest.data !== undefined}
                  hasExistingThreats={alreadyAdded.size > 0}
                  searchQuery={searchQuery}
                  selectedThreatId={selectedThreatId}
                  onSelect={(suggestion) => {
                    setSelectedThreatId(suggestion.threatLibrary)
                    setSelectedLevel(suggestion.suggestedSeverity)
                  }}
                  onRetry={() => singleComponentId !== null && suggest.mutate({ targetId: singleComponentId })}
                />
              ) : isLoading ? (
                <div className="p-4 text-center text-muted-foreground">Loading threats</div>
              ) : filteredThreats.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground">
                  {searchQuery
                    ? 'No threats match your search'
                    : threatLibrary && threatLibrary.length > 0
                      ? `Every applicable threat is already on ${targetName}.`
                      : 'No threats available in the library'}
                </div>
              ) : (
                <div className="space-y-1 p-2">
                  {filteredThreats.map((threat) => (
                    <button
                      key={threat.id}
                      onClick={() => setSelectedThreatId(threat.id)}
                      className={cn(
                        'w-full rounded-md p-3 text-left transition-colors',
                        selectedThreatId === threat.id ? 'border border-primary bg-primary/10' : 'hover:bg-muted'
                      )}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium">{threat.name}</span>
                        {(threat.description || (threat.taxonomyEntries && threat.taxonomyEntries.length > 0)) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Info className="h-3.5 w-3.5 shrink-0 cursor-help text-muted-foreground" />
                            </TooltipTrigger>
                            <TooltipContent side="right" className="max-w-xs">
                              {threat.description && <p>{threat.description}</p>}
                              {threat.taxonomyEntries && threat.taxonomyEntries.length > 0 && (
                                <p className="mt-1 opacity-75">
                                  {threat.taxonomyEntries.map((entry) => entry.title).join(' · ')}
                                </p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>

            {selectedThreatName && (
              <div className="space-y-3 rounded-md bg-muted/50 p-3">
                <div>
                  <Label className="text-xs text-muted-foreground">Selected threat</Label>
                  <p className="font-medium">{selectedThreatName}</p>
                </div>
                <div className="flex-1">
                  <Label htmlFor="library-level">Level</Label>
                  {levelSelect('library-level', selectedLevel, setSelectedLevel)}
                </div>
              </div>
            )}

            {appliesToSection}
          </TabsContent>

          <TabsContent value="custom" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="custom-name">Threat name *</Label>
              <Input
                id="custom-name"
                placeholder="Threat name"
                value={customName}
                onChange={(event) => setCustomName(event.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="custom-description">Description</Label>
              <Textarea
                id="custom-description"
                placeholder="Describe the threat"
                value={customDescription}
                onChange={(event) => setCustomDescription(event.target.value)}
                rows={3}
              />
            </div>

            <div className="flex gap-4">
              <div className="flex-1 space-y-2">
                <Label htmlFor="custom-level">Level *</Label>
                {levelSelect('custom-level', customLevel, setCustomLevel)}
              </div>
              <div className="flex-1 space-y-2">
                <Label htmlFor="custom-triage-status">Status</Label>
                <Select value={customTriageStatus} onValueChange={(value) => setCustomTriageStatus(value as TriageStatus)}>
                  <SelectTrigger id="custom-triage-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TRIAGE_STATUSES.map((entry) => (
                      <SelectItem key={entry.value} value={entry.value}>
                        {entry.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {taxonomyEntriesByTaxonomy.length > 0 && (
              <div className="space-y-2">
                <Label htmlFor="custom-taxonomy">Taxonomy category</Label>
                <Select value={customTaxonomyEntryId} onValueChange={setCustomTaxonomyEntryId}>
                  <SelectTrigger id="custom-taxonomy">
                    <SelectValue placeholder="None" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None</SelectItem>
                    {taxonomyEntriesByTaxonomy.map(([taxonomyName, entries]) =>
                      entries.map((entry) => (
                        <SelectItem key={entry.id} value={String(entry.id)}>
                          {taxonomyEntriesByTaxonomy.length > 1
                            ? `${taxonomyName}: ${formatTaxonomyEntryLabel(entry)}`
                            : formatTaxonomyEntryLabel(entry)}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
            )}

            {appliesToSection}

            <div className="flex items-center gap-2 rounded-md bg-muted/50 p-3 text-sm text-muted-foreground">
              <FileText className="h-4 w-4 shrink-0" />
              <p>Custom threats are not linked to the threat library and get no generated countermeasures.</p>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {activeTab === 'library' ? (
            <Button onClick={handleAddFromLibrary} disabled={!selectedThreatId || !targetsValid || isSubmitting}>
              <Plus className="mr-2 h-4 w-4" />
              Add threat
            </Button>
          ) : (
            <Button onClick={handleAddCustom} disabled={!customName.trim() || !targetsValid || isSubmitting}>
              <Plus className="mr-2 h-4 w-4" />
              Add custom threat
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The ranked view of the same list: each row keeps the model's reasoning
 * and suggested level next to the threat. The pool is narrower than the
 * plain list by design: the backend excludes threats already on the
 * component.
 */
function RankedList({
  pending,
  error,
  suggestions,
  hasResults,
  hasExistingThreats,
  searchQuery,
  selectedThreatId,
  onSelect,
  onRetry,
}: {
  pending: boolean
  error: unknown
  suggestions: ThreatSuggestion[]
  hasResults: boolean
  hasExistingThreats: boolean
  searchQuery: string
  selectedThreatId: number | null
  onSelect: (suggestion: ThreatSuggestion) => void
  onRetry: () => void
}) {
  if (pending) {
    return (
      <div className="flex items-center justify-center gap-2 p-4 py-12 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Ranking relevant threats
      </div>
    )
  }

  if (error) {
    return <AiErrorState error={error} fallbackMessage="Something went wrong ranking these threats." onRetry={onRetry} />
  }

  if (!hasResults) return null

  if (suggestions.length === 0) {
    return (
      <div className="p-4 py-10 text-center text-sm text-muted-foreground">
        {searchQuery
          ? 'No ranked threats match your search'
          : hasExistingThreats
            ? 'Nothing left to suggest: every applicable threat is already on this component.'
            : 'No suggestions for this component. It is not linked to a component library, so there is nothing to ground suggestions in.'}
      </div>
    )
  }

  return (
    <div className="space-y-1 p-2">
      {suggestions.map((suggestion) => (
        <button
          key={suggestion.threatLibrary}
          onClick={() => onSelect(suggestion)}
          className={cn(
            'w-full rounded-md p-3 text-left transition-colors',
            selectedThreatId === suggestion.threatLibrary ? 'border border-primary bg-primary/10' : 'hover:bg-muted'
          )}
        >
          <div className="flex items-center gap-1.5">
            <span className="font-medium">{suggestion.threatName}</span>
            <Badge variant="outline" className={cn('shrink-0 text-[10px] capitalize', RATING_LEVEL_CLASSES[suggestion.suggestedSeverity])}>
              {suggestion.suggestedSeverity}
            </Badge>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{suggestion.rationale}</p>
          {suggestion.source.packName && (
            <p className="mt-1 text-[11px] text-muted-foreground/75">from {suggestion.source.packName}</p>
          )}
        </button>
      ))}
    </div>
  )
}
