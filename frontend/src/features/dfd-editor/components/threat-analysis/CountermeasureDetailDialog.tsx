/**
 * The countermeasure modal (UX simplification 3.4): everything about one
 * countermeasure of the selected threat that used to sit on its card. Status
 * (the five buttons, the waiver reason, the owner prompt for Planned),
 * description and type, tracking (owner, due, priority, ticket), compliance
 * coverage, Advanced (effectiveness, implemented by, source), the threats it
 * mitigates (each switches to that threat), Applies to, and Remove or Delete.
 * Saves work as they did on the card: each tracking field and status at once,
 * Advanced with its own Save. Scope changes no threat's status (L4).
 */

import { useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { ChevronDown, ChevronRight, Loader2, Pencil, Shield, Trash2, User } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { cn } from '@/lib/utils'
import { CONTROL_FUNCTIONS, CONTROL_NATURES } from '@/types/controls'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import {
  useCountermeasure,
  useSetCountermeasureTargets,
  useUpdateCountermeasure,
  type TargetRef,
} from '@/features/threat-models/api/threats'
import type { AnalysisCountermeasure, AnalysisThreat, CountermeasureStatus } from '../../types/threat-analysis'
import { ComplianceDetailSection } from './ComplianceDetailSection'
import { CountermeasureStatusButtons } from './CountermeasureStatusButtons'
import { CountermeasureStatusDot, type Assignee } from './CountermeasureCard'
import { UserSearchCombobox } from './UserSearchCombobox'
import { WaiverReasonInput } from './WaiverReasonInput'
import { NumberBadge } from './NumberBadge'
import { EditTargetsDialog } from './EditTargetsDialog'
import {
  PRIORITY_CONFIG,
  effectivenessFromInput,
  effectivenessToInput,
  formatAlsoMitigatesLine,
  formatTargetList,
} from './countermeasure-utils'

export interface CountermeasureDetailDialogProps {
  threatModelId: string
  /** The selected threat; the modal shows one of its countermeasures. */
  threat: AnalysisThreat
  /** The countermeasure shown; null closes the modal. */
  countermeasure: AnalysisCountermeasure | null
  onClose: () => void
  isSecurityTeam?: boolean
  onStatusChange: (countermeasureId: string, status: CountermeasureStatus, notes?: string) => void
  onAssignOwner: (countermeasureId: string, assignee: Assignee, newStatus?: CountermeasureStatus) => void
  onPriorityChange: (countermeasureId: string, priority: AnalysisCountermeasure['priority']) => void
  onDueDateChange: (countermeasureId: string, dueDate: string | null) => void
  onExternalTicketChange: (countermeasureId: string, externalTicketUrl: string) => void
  onRequestDelete: (countermeasure: AnalysisCountermeasure) => void
  onEditCompliance: (countermeasure: AnalysisCountermeasure) => void
  /** Switch to another threat this control mitigates, by its backend id. */
  onOpenThreat: (threatId: number) => void
}

export function CountermeasureDetailDialog({ countermeasure, onClose, ...rest }: CountermeasureDetailDialogProps) {
  return (
    <Dialog
      open={countermeasure !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className="sm:max-w-[720px]" data-testid="countermeasure-detail-dialog">
        {/* Keyed by countermeasure, so the prompts start closed for each one. */}
        {countermeasure && (
          <CountermeasureDetailContent key={countermeasure.id} countermeasure={countermeasure} onClose={onClose} {...rest} />
        )}
      </DialogContent>
    </Dialog>
  )
}

function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      {children}
    </div>
  )
}

function CountermeasureDetailContent({
  threatModelId,
  threat,
  countermeasure,
  onClose,
  isSecurityTeam,
  onStatusChange,
  onAssignOwner,
  onPriorityChange,
  onDueDateChange,
  onExternalTicketChange,
  onRequestDelete,
  onEditCompliance,
  onOpenThreat,
}: Omit<CountermeasureDetailDialogProps, 'countermeasure'> & { countermeasure: AnalysisCountermeasure }) {
  const backendId = countermeasure.backendCountermeasureId ?? null
  const name = countermeasure.countermeasureName || countermeasure.countermeasureId

  const [assigningOwner, setAssigningOwner] = useState(false)
  const [pendingPlanned, setPendingPlanned] = useState(false)
  const [waiving, setWaiving] = useState(false)
  const [complianceOpen, setComplianceOpen] = useState(true)
  const [scopeOpen, setScopeOpen] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)

  const setTargets = useSetCountermeasureTargets()
  const today = new Date().toISOString().split('T')[0]
  const hasType = (countermeasure.controlFunctions && countermeasure.controlFunctions.length > 0) || countermeasure.controlNature

  const linkedThreats = useMemo(
    () => [
      { threatId: threat.backendThreatId, displayNumber: threat.displayNumber, current: true },
      ...(countermeasure.alsoMitigates ?? []).map((entry) => ({
        threatId: entry.threatId,
        displayNumber: entry.displayNumber,
        current: false,
      })),
    ],
    [threat.backendThreatId, threat.displayNumber, countermeasure.alsoMitigates]
  )

  return (
    <>
      <DialogHeader className="pr-8">
        <DialogTitle className="flex items-center gap-2 text-base">
          <NumberBadge number={countermeasure.displayNumber} className="text-xs" />
          <span className="truncate">{name}</span>
        </DialogTitle>
        <DialogDescription asChild>
          <div className="flex flex-wrap items-center gap-2">
            <CountermeasureStatusDot status={countermeasure.status} />
            <span className="text-xs text-muted-foreground">
              for <NumberBadge number={threat.displayNumber} /> {threat.threatName}
            </span>
          </div>
        </DialogDescription>
      </DialogHeader>

      <Section title="Status">
        {assigningOwner ? (
          <div>
            <div className="mb-2 text-xs text-muted-foreground">
              {pendingPlanned ? 'Assign an owner to mark as Planned:' : 'Assign owner:'}
            </div>
            <UserSearchCombobox
              value={countermeasure.owner || ''}
              onSelect={(assignee) => {
                onAssignOwner(countermeasure.id, assignee, pendingPlanned ? 'planned' : undefined)
                setAssigningOwner(false)
                setPendingPlanned(false)
              }}
              onCancel={() => {
                setAssigningOwner(false)
                setPendingPlanned(false)
              }}
            />
          </div>
        ) : waiving ? (
          <WaiverReasonInput
            onSubmit={(reason) => {
              onStatusChange(countermeasure.id, 'waived', reason)
              setWaiving(false)
            }}
            onCancel={() => setWaiving(false)}
          />
        ) : (
          <CountermeasureStatusButtons
            status={countermeasure.status}
            isPlatformLevel={countermeasure.status === 'platform'}
            isSecurityTeam={isSecurityTeam}
            hasOwner={!!countermeasure.owner}
            onChange={(status) => onStatusChange(countermeasure.id, status)}
            onPlannedWithoutOwner={() => {
              setAssigningOwner(true)
              setPendingPlanned(true)
            }}
            onWaivedWithoutReason={() => setWaiving(true)}
          />
        )}
        {countermeasure.status === 'waived' && countermeasure.notes && !waiving && (
          <div className="rounded border border-blue-200 bg-blue-50 p-2 text-xs text-muted-foreground">
            <span className="font-medium text-blue-700">Waiver reason:</span> {countermeasure.notes}
          </div>
        )}
      </Section>

      {(countermeasure.countermeasureDescription || hasType) && (
        <Section title="Description and type">
          {countermeasure.countermeasureDescription && <p className="text-sm">{countermeasure.countermeasureDescription}</p>}
          {hasType && (
            <div className="flex flex-wrap items-center gap-1.5">
              {countermeasure.controlFunctions?.map((controlFunction) => (
                <Badge key={controlFunction} variant="outline" className="text-xs capitalize">
                  {CONTROL_FUNCTIONS.find((entry) => entry.value === controlFunction)?.label || controlFunction}
                </Badge>
              ))}
              {countermeasure.controlNature && (
                <Badge variant="secondary" className="text-xs capitalize">
                  {CONTROL_NATURES.find((entry) => entry.value === countermeasure.controlNature)?.label ||
                    countermeasure.controlNature}
                </Badge>
              )}
            </div>
          )}
        </Section>
      )}

      <Section title="Tracking">
        <div className="grid grid-cols-[80px_1fr] items-center gap-x-3 gap-y-2 text-xs">
          <span className="text-muted-foreground">Owner</span>
          <div className="flex items-center gap-2">
            {countermeasure.owner ? (
              <span className="flex items-center gap-1 text-blue-600">
                <User className="h-3 w-3" />
                {countermeasure.owner}
              </span>
            ) : (
              <span className="text-muted-foreground">None</span>
            )}
            {countermeasure.status !== 'platform' && !assigningOwner && (
              <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setAssigningOwner(true)}>
                {countermeasure.owner ? 'Change owner' : 'Assign owner'}
              </Button>
            )}
          </div>

          <span className="text-muted-foreground">Due</span>
          <input
            type="date"
            value={countermeasure.dueDate || ''}
            onChange={(event) => onDueDateChange(countermeasure.id, event.target.value ? event.target.value : null)}
            className={cn(
              'h-7 w-fit rounded border bg-background px-2 text-xs',
              countermeasure.dueDate && countermeasure.dueDate < today ? 'border-red-500 bg-red-50 text-red-600' : ''
            )}
            aria-label="Due date"
          />

          <span className="text-muted-foreground">Priority</span>
          <Select
            value={countermeasure.priority || 'none'}
            onValueChange={(value) => onPriorityChange(countermeasure.id, value as AnalysisCountermeasure['priority'])}
          >
            <SelectTrigger className="h-7 w-28 text-xs" aria-label="Priority">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Object.entries(PRIORITY_CONFIG).map(([key, config]) => (
                <SelectItem key={key} value={key}>
                  <Badge variant="outline" className={cn('text-[10px]', config.color)}>
                    {config.label}
                  </Badge>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <span className="text-muted-foreground">Ticket</span>
          <input
            type="url"
            placeholder="https://..."
            value={countermeasure.externalTicketUrl || ''}
            onChange={(event) => onExternalTicketChange(countermeasure.id, event.target.value)}
            className="h-7 w-full min-w-0 rounded border bg-background px-2 text-xs"
            aria-label="Ticket link"
          />
        </div>
      </Section>

      {/* ComplianceDetailSection carries its own "Compliance Coverage" heading. */}
      {countermeasure.standardMappings && countermeasure.standardMappings.length > 0 ? (
        <ComplianceDetailSection
          mappings={countermeasure.standardMappings}
          isExpanded={complianceOpen}
          onToggle={() => setComplianceOpen((open) => !open)}
          onEdit={backendId !== null ? () => onEditCompliance(countermeasure) : undefined}
        />
      ) : (
        <Section title="Compliance coverage">
          {backendId !== null ? (
            <button
              className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700"
              onClick={() => onEditCompliance(countermeasure)}
            >
              <Shield className="h-3 w-3" />
              <span>Add compliance mapping</span>
            </button>
          ) : (
            <p className="text-xs text-muted-foreground">No compliance mapping.</p>
          )}
        </Section>
      )}

      {backendId !== null && (
        <div>
          <button
            type="button"
            className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
            onClick={() => setAdvancedOpen((open) => !open)}
            aria-expanded={advancedOpen}
          >
            {advancedOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            Advanced
          </button>
          {advancedOpen && (
            <CountermeasureAdvancedEditor
              threatModelId={threatModelId}
              countermeasureId={backendId}
              fallback={countermeasure}
            />
          )}
        </div>
      )}

      <Section title="Mitigates">
        <div className="flex flex-wrap items-center gap-1 text-xs">
          {linkedThreats.map((link) => (
            <NumberBadge
              key={link.threatId}
              number={link.displayNumber}
              className={cn(link.current && 'border-slate-500 bg-slate-200')}
              onClick={link.current ? undefined : () => onOpenThreat(link.threatId)}
              title={link.current ? 'This threat' : 'Open this threat'}
            />
          ))}
        </div>
        {countermeasure.alsoMitigates && countermeasure.alsoMitigates.length > 0 && (
          <ul className="space-y-0.5 text-xs" data-testid="also-mitigates">
            {countermeasure.alsoMitigates.map((entry) => (
              <li key={entry.threatId}>
                <button type="button" className="text-left text-blue-600 hover:underline" onClick={() => onOpenThreat(entry.threatId)}>
                  {formatAlsoMitigatesLine(entry)}
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Applies to">
        <div className="flex items-center gap-2 text-xs">
          <span className="min-w-0 truncate">{formatTargetList(countermeasure.targets ?? [], 3)}</span>
          {backendId !== null && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 gap-1 px-1.5 text-xs text-blue-600 hover:text-blue-700"
              onClick={() => setScopeOpen(true)}
            >
              <Pencil className="h-3 w-3" /> Edit
            </Button>
          )}
        </div>
      </Section>

      <DialogFooter className="sm:justify-between">
        {backendId !== null ? (
          <Button
            variant="ghost"
            size="sm"
            className="gap-1 text-destructive hover:bg-red-50 hover:text-destructive"
            onClick={() => onRequestDelete(countermeasure)}
          >
            <Trash2 className="h-3.5 w-3.5" />
            {countermeasure.isShared ? 'Remove from this threat' : 'Delete countermeasure'}
          </Button>
        ) : (
          <span />
        )}
        <Button variant="outline" size="sm" onClick={onClose}>
          Close
        </Button>
      </DialogFooter>

      {backendId !== null && scopeOpen && (
        <EditTargetsDialog
          open
          onOpenChange={setScopeOpen}
          threatModelId={threatModelId}
          title={`${countermeasure.displayNumber ?? ''} Applies to`.trim()}
          initialTargets={(countermeasure.targets ?? []).map((target): TargetRef => ({ type: target.type, id: target.id }))}
          mode="countermeasure"
          isSaving={setTargets.isPending}
          onSave={(targets) => {
            setTargets.mutate(
              { countermeasureId: backendId, targets },
              {
                onSuccess: () => {
                  toast.success('Scope saved')
                  setScopeOpen(false)
                },
                onError: () => toast.error('Could not save the scope'),
              }
            )
          }}
        />
      )}
    </>
  )
}

/**
 * Effectiveness, implemented by and source (plan J3, J13). The analysis
 * payload does not carry the effectiveness, so the row is read on demand and
 * the form mounts once it is here.
 */
function CountermeasureAdvancedEditor({
  threatModelId,
  countermeasureId,
  fallback,
}: {
  threatModelId: string
  countermeasureId: number
  fallback: AnalysisCountermeasure
}) {
  const { data: detail, isLoading } = useCountermeasure(countermeasureId)
  if (isLoading || !detail) {
    return (
      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" /> Loading
      </div>
    )
  }
  return (
    <CountermeasureAdvancedForm
      key={`${detail.id}-${detail.updatedAt}`}
      threatModelId={threatModelId}
      countermeasureId={countermeasureId}
      initialEffectiveness={effectivenessToInput(detail.effectiveness)}
      initialImplementedBy={detail.implementedBy ?? fallback.implementedBy ?? []}
      initialImplementedByParty={detail.implementedByParty ?? fallback.implementedByParty ?? ''}
      initialSource={detail.source ?? fallback.source ?? ''}
    />
  )
}

function CountermeasureAdvancedForm({
  threatModelId,
  countermeasureId,
  initialEffectiveness,
  initialImplementedBy,
  initialImplementedByParty,
  initialSource,
}: {
  threatModelId: string
  countermeasureId: number
  initialEffectiveness: string
  initialImplementedBy: number[]
  initialImplementedByParty: string
  initialSource: string
}) {
  const { data: components = [] } = useAnalysisComponents(threatModelId)
  const updateCountermeasure = useUpdateCountermeasure()

  const [effectiveness, setEffectiveness] = useState(initialEffectiveness)
  const [implementedBy, setImplementedBy] = useState<number[]>(initialImplementedBy)
  const [implementedByParty, setImplementedByParty] = useState(initialImplementedByParty)
  const [source, setSource] = useState(initialSource)

  const parsedEffectiveness = effectivenessFromInput(effectiveness)
  const effectivenessInvalid = parsedEffectiveness === undefined

  const handleSave = () => {
    if (effectivenessInvalid) return
    updateCountermeasure.mutate(
      {
        countermeasureId,
        data: { effectiveness: parsedEffectiveness, implementedBy, implementedByParty, source },
      },
      {
        onSuccess: () => toast.success('Countermeasure saved'),
        onError: () => toast.error('Could not save the countermeasure'),
      }
    )
  }

  const componentOptions = useMemo(
    () => components.map((component) => ({ value: String(component.id), label: component.name })),
    [components]
  )

  return (
    <div className="mt-2 space-y-2">
      <div className="space-y-1">
        <Label htmlFor={`cm-${countermeasureId}-effectiveness`} className="text-xs">
          Effectiveness
        </Label>
        <div className="flex items-center gap-2">
          <Input
            id={`cm-${countermeasureId}-effectiveness`}
            type="number"
            min={0}
            max={100}
            step={1}
            placeholder="not assessed"
            value={effectiveness}
            onChange={(event) => setEffectiveness(event.target.value)}
            className={cn('h-7 w-28 text-xs', effectivenessInvalid && 'border-red-500')}
          />
          <span className="text-xs text-muted-foreground">
            {effectiveness.trim() === '' ? 'Not assessed' : '%'}
          </span>
          {effectiveness.trim() !== '' && (
            <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => setEffectiveness('')}>
              Clear
            </Button>
          )}
        </div>
        {effectivenessInvalid && <p className="text-[11px] text-red-600">Give a whole number from 0 to 100.</p>}
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Implemented by: components</Label>
        <MultiSelectCombobox
          options={componentOptions}
          selected={implementedBy.map(String)}
          onChange={(selected) => setImplementedBy(selected.map(Number))}
          placeholder="Components that implement this control"
          searchPlaceholder="Search components"
          emptyMessage="No component matches"
        />
      </div>
      <div className="space-y-1">
        <Label htmlFor={`cm-${countermeasureId}-party`} className="text-xs">
          Implemented by: other party
        </Label>
        <Input
          id={`cm-${countermeasureId}-party`}
          value={implementedByParty}
          onChange={(event) => setImplementedByParty(event.target.value)}
          placeholder="A cloud provider, another team"
          className="h-7 text-xs"
        />
      </div>
      <div className="space-y-1">
        <Label htmlFor={`cm-${countermeasureId}-source`} className="text-xs">
          Source
        </Label>
        <Input
          id={`cm-${countermeasureId}-source`}
          value={source}
          onChange={(event) => setSource(event.target.value)}
          placeholder="Where the control came from, for example a compliance tool or a pentest"
          className="h-7 text-xs"
        />
      </div>
      <Button
        size="sm"
        variant="outline"
        className="h-7 text-xs"
        onClick={handleSave}
        disabled={updateCountermeasure.isPending || effectivenessInvalid}
      >
        {updateCountermeasure.isPending ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : null}
        Save advanced
      </Button>
    </div>
  )
}
