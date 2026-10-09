/**
 * A risk's responses (plan 11.4, 11.11 Risk row): strategy, description,
 * status, owner and target date in the table; cost, priority and the linked
 * countermeasures under a collapsed Advanced section of the row dialog.
 * Replaces the response select the risk used to carry.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ChevronDown, ChevronRight, Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { MultiSelectCombobox, type ComboboxOption } from '@/components/ui/multi-select-combobox'
import {
  useCreateRiskResponse,
  useDeleteRiskResponse,
  useRiskResponses,
  useUpdateRiskResponse,
} from '@/features/threat-models/api/risks'
import { useCountermeasuresInUse } from '@/features/threat-models/api/threats'
import type { ComponentThreat } from '@/features/dfd-editor/types/threat-analysis'
import {
  RISK_RESPONSE_COSTS,
  RISK_RESPONSE_PRIORITIES,
  RISK_RESPONSE_STATUSES,
  RISK_RESPONSE_STRATEGIES,
  type CreateRiskResponseInput,
  type RiskResponse,
  type RiskResponseCost,
  type RiskResponsePriority,
  type RiskResponseStatus,
  type RiskResponseStrategy,
} from '@/types/risk'
import { apiErrorMessage, formatTargetDate } from './risk-utils'

const NO_OWNER = '_none'
const NO_VALUE = '_none'

const STRATEGY_LABELS = Object.fromEntries(RISK_RESPONSE_STRATEGIES.map((entry) => [entry.value, entry.label]))
const RESPONSE_STATUS_LABELS = Object.fromEntries(RISK_RESPONSE_STATUSES.map((entry) => [entry.value, entry.label]))

export interface OwnerOption {
  userId: number
  email: string
}

/**
 * The model's countermeasures as combobox options, labelled `C3 Name`. The
 * in-use endpoint lists every control; display numbers come from the
 * analysis payload where a control is linked to a threat there.
 */
function useCountermeasureOptions(threatModelId: string, componentThreats: ComponentThreat[]): ComboboxOption[] {
  const { data: inUse } = useCountermeasuresInUse(threatModelId)
  return useMemo(() => {
    const numberById = new Map<number, string>()
    for (const threat of componentThreats) {
      for (const countermeasure of threat.countermeasures) {
        if (countermeasure.backendCountermeasureId && countermeasure.displayNumber) {
          numberById.set(countermeasure.backendCountermeasureId, countermeasure.displayNumber)
        }
      }
    }
    return (inUse?.countermeasures ?? []).map((countermeasure) => {
      const number = numberById.get(countermeasure.id)
      const name = countermeasure.countermeasureName ?? `Countermeasure #${countermeasure.id}`
      return {
        value: String(countermeasure.id),
        label: number ? `${number} ${name}` : name,
        meta: countermeasure.status,
      }
    })
  }, [inUse, componentThreats])
}

interface ResponseFormState {
  strategy: RiskResponseStrategy
  description: string
  status: RiskResponseStatus
  owner: number | null
  targetDate: string
  cost: RiskResponseCost | ''
  priority: RiskResponsePriority | ''
  countermeasureIds: number[]
}

function emptyResponseForm(): ResponseFormState {
  return {
    strategy: 'reduce',
    description: '',
    status: 'planned',
    owner: null,
    targetDate: '',
    cost: '',
    priority: '',
    countermeasureIds: [],
  }
}

function responseFormFromResponse(response: RiskResponse): ResponseFormState {
  return {
    strategy: response.strategy,
    description: response.description,
    status: response.status,
    owner: response.owner,
    targetDate: response.targetDate ?? '',
    cost: response.cost,
    priority: response.priority,
    countermeasureIds: response.countermeasureIds ?? response.countermeasures.map((entry) => entry.id),
  }
}

function responseInputFromForm(form: ResponseFormState): CreateRiskResponseInput {
  return {
    strategy: form.strategy,
    description: form.description,
    status: form.status,
    owner: form.owner,
    targetDate: form.targetDate || null,
    cost: form.cost,
    priority: form.priority,
    countermeasureIds: form.countermeasureIds,
  }
}

function ResponseDialog({
  open,
  onOpenChange,
  initial,
  title,
  submitLabel,
  pending,
  owners,
  countermeasureOptions,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  initial: ResponseFormState
  title: string
  submitLabel: string
  pending: boolean
  owners: OwnerOption[]
  countermeasureOptions: ComboboxOption[]
  onSubmit: (input: CreateRiskResponseInput) => void
}) {
  const [form, setForm] = useState<ResponseFormState>(initial)
  const [showAdvanced, setShowAdvanced] = useState(
    Boolean(initial.cost || initial.priority || initial.countermeasureIds.length > 0)
  )

  const patch = (changes: Partial<ResponseFormState>) => setForm((previous) => ({ ...previous, ...changes }))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>What will be done about this risk, and by when.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="response-strategy">Strategy</Label>
              <Select value={form.strategy} onValueChange={(value) => patch({ strategy: value as RiskResponseStrategy })}>
                <SelectTrigger id="response-strategy" aria-label="Strategy">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RISK_RESPONSE_STRATEGIES.map((entry) => (
                    <SelectItem key={entry.value} value={entry.value}>
                      {entry.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="response-status">Status</Label>
              <Select value={form.status} onValueChange={(value) => patch({ status: value as RiskResponseStatus })}>
                <SelectTrigger id="response-status" aria-label="Response status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RISK_RESPONSE_STATUSES.map((entry) => (
                    <SelectItem key={entry.value} value={entry.value}>
                      {entry.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="response-description">Description</Label>
            <Textarea
              id="response-description"
              value={form.description}
              rows={2}
              placeholder="What will be done"
              onChange={(event) => patch({ description: event.target.value })}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="response-owner">Owner</Label>
              <Select
                value={form.owner === null ? NO_OWNER : String(form.owner)}
                onValueChange={(value) => patch({ owner: value === NO_OWNER ? null : Number(value) })}
              >
                <SelectTrigger id="response-owner" aria-label="Response owner">
                  <SelectValue placeholder="Select owner" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_OWNER}>No owner</SelectItem>
                  {owners.map((owner) => (
                    <SelectItem key={owner.userId} value={String(owner.userId)}>
                      {owner.email}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="response-target-date">Target date</Label>
              <Input
                id="response-target-date"
                type="date"
                value={form.targetDate}
                onChange={(event) => patch({ targetDate: event.target.value })}
              />
            </div>
          </div>

          <div className="border-t pt-2">
            <button
              type="button"
              className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
              onClick={() => setShowAdvanced((openState) => !openState)}
              aria-expanded={showAdvanced}
            >
              {showAdvanced ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              Advanced
            </button>
            {showAdvanced && (
              <div className="mt-3 space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label htmlFor="response-cost" className="text-xs">
                      Cost
                    </Label>
                    <Select
                      value={form.cost || NO_VALUE}
                      onValueChange={(value) => patch({ cost: value === NO_VALUE ? '' : (value as RiskResponseCost) })}
                    >
                      <SelectTrigger id="response-cost" className="h-8 text-xs" aria-label="Cost">
                        <SelectValue placeholder="Not set" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={NO_VALUE}>Not set</SelectItem>
                        {RISK_RESPONSE_COSTS.map((entry) => (
                          <SelectItem key={entry.value} value={entry.value}>
                            {entry.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="response-priority" className="text-xs">
                      Priority
                    </Label>
                    <Select
                      value={form.priority || NO_VALUE}
                      onValueChange={(value) =>
                        patch({ priority: value === NO_VALUE ? '' : (value as RiskResponsePriority) })
                      }
                    >
                      <SelectTrigger id="response-priority" className="h-8 text-xs" aria-label="Priority">
                        <SelectValue placeholder="Not set" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={NO_VALUE}>Not set</SelectItem>
                        {RISK_RESPONSE_PRIORITIES.map((entry) => (
                          <SelectItem key={entry.value} value={entry.value}>
                            {entry.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Linked countermeasures</Label>
                  <MultiSelectCombobox
                    options={countermeasureOptions}
                    selected={form.countermeasureIds.map(String)}
                    onChange={(selected) => patch({ countermeasureIds: selected.map(Number) })}
                    placeholder="Controls this response relies on"
                    searchPlaceholder="Search countermeasures"
                    emptyMessage="No countermeasures in this model."
                  />
                </div>
              </div>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => onSubmit(responseInputFromForm(form))} disabled={pending}>
            {pending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            {submitLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export interface RiskResponsesTableProps {
  threatModelId: string
  riskId: number
  /** The detail serializer's nested responses, shown until the responses query answers. */
  initialResponses?: RiskResponse[]
  owners: OwnerOption[]
  componentThreats: ComponentThreat[]
}

export function RiskResponsesTable({
  threatModelId,
  riskId,
  initialResponses,
  owners,
  componentThreats,
}: RiskResponsesTableProps) {
  const { data: fetchedResponses } = useRiskResponses(threatModelId, riskId)
  const responses = fetchedResponses ?? initialResponses ?? []
  const createResponse = useCreateRiskResponse(threatModelId)
  const updateResponse = useUpdateRiskResponse(threatModelId)
  const deleteResponse = useDeleteRiskResponse(threatModelId)
  const countermeasureOptions = useCountermeasureOptions(threatModelId, componentThreats)

  const [addOpen, setAddOpen] = useState(false)
  const [editing, setEditing] = useState<RiskResponse | null>(null)
  const [deleting, setDeleting] = useState<RiskResponse | null>(null)

  const handleCreate = (input: CreateRiskResponseInput) => {
    createResponse.mutate(
      { riskId, data: input },
      {
        onSuccess: () => setAddOpen(false),
        onError: (error) => toast.error(apiErrorMessage(error, 'Failed to add the response.')),
      }
    )
  }

  const handleUpdate = (input: CreateRiskResponseInput) => {
    if (!editing) return
    updateResponse.mutate(
      { riskId, responseId: editing.id, data: input },
      {
        onSuccess: () => setEditing(null),
        onError: (error) => toast.error(apiErrorMessage(error, 'Failed to save the response.')),
      }
    )
  }

  const handleDelete = () => {
    if (!deleting) return
    deleteResponse.mutate(
      { riskId, responseId: deleting.id },
      {
        onSuccess: () => setDeleting(null),
        onError: (error) => toast.error(apiErrorMessage(error, 'Failed to delete the response.')),
      }
    )
  }

  return (
    <div className="space-y-2" data-testid="risk-responses">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">Responses ({responses.length})</p>
        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setAddOpen(true)}>
          <Plus className="h-3 w-3 mr-1" />
          Add response
        </Button>
      </div>
      {responses.length === 0 ? (
        <p className="text-sm text-muted-foreground border border-dashed rounded-md px-3 py-2">
          No responses yet. Add one to say how the risk is handled.
        </p>
      ) : (
        <div className="border rounded-md overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[90px]">Strategy</TableHead>
                <TableHead>Description</TableHead>
                <TableHead className="w-[110px]">Status</TableHead>
                <TableHead className="w-[150px]">Owner</TableHead>
                <TableHead className="w-[110px]">Target date</TableHead>
                <TableHead className="w-[70px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {responses.map((response) => (
                <TableRow key={response.id} data-testid="risk-response-row">
                  <TableCell className="text-sm font-medium">{STRATEGY_LABELS[response.strategy] ?? response.strategy}</TableCell>
                  <TableCell className="text-sm">
                    <div>{response.description || <span className="text-muted-foreground">No description</span>}</div>
                    {response.countermeasures.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {response.countermeasures.map((countermeasure) => (
                          <Badge
                            key={countermeasure.id}
                            variant="outline"
                            className="text-[10px] font-mono"
                            title={countermeasure.countermeasureName}
                          >
                            {countermeasure.displayNumber}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{RESPONSE_STATUS_LABELS[response.status] ?? response.status}</TableCell>
                  <TableCell className="text-sm text-muted-foreground truncate">{response.ownerEmail ?? '-'}</TableCell>
                  <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                    {formatTargetDate(response.targetDate)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                      aria-label="Edit response"
                      onClick={() => setEditing(response)}
                    >
                      <Pencil className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                      aria-label="Delete response"
                      onClick={() => setDeleting(response)}
                    >
                      <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {addOpen && (
        <ResponseDialog
          open={addOpen}
          onOpenChange={setAddOpen}
          initial={emptyResponseForm()}
          title="Add response"
          submitLabel="Add response"
          pending={createResponse.isPending}
          owners={owners}
          countermeasureOptions={countermeasureOptions}
          onSubmit={handleCreate}
        />
      )}
      {editing && (
        <ResponseDialog
          key={editing.id}
          open={Boolean(editing)}
          onOpenChange={(open) => !open && setEditing(null)}
          initial={responseFormFromResponse(editing)}
          title="Edit response"
          submitLabel="Save"
          pending={updateResponse.isPending}
          owners={owners}
          countermeasureOptions={countermeasureOptions}
          onSubmit={handleUpdate}
        />
      )}

      <AlertDialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete response</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the response from the risk. Linked countermeasures are kept.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deleteResponse.isPending}>
              {deleteResponse.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
