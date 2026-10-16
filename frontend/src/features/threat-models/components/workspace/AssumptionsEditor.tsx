/**
 * Assumptions as rows with their own API calls (plan 11.5, 11.11
 * "Assumption" row). Description and validity are always shown; topic,
 * impact, owner, validation method and date, and the related components sit
 * under "More". Text fields save on blur, selects on change.
 */

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import {
  ASSUMPTION_TOPICS,
  ASSUMPTION_VALIDITY,
  type AssumptionTopic,
  type AssumptionValidity,
} from '@/types/domain'
import {
  useAssumptions,
  useCreateAssumption,
  useDeleteAssumption,
  useUpdateAssumption,
} from '@/features/threat-models/api/threat-models'
import { useAnalysisComponents, type OrgsystemComponent } from '@/features/threat-models/api/components'
import type { Assumption, UpdateAssumptionInput } from '@/features/threat-models/types/core'

const TOPIC_NONE = 'none'

function validityBadgeClass(validity: AssumptionValidity): string {
  switch (validity) {
    case 'verified':
      return 'border-green-300 bg-green-50 text-green-700'
    case 'invalid':
      return 'border-red-300 bg-red-50 text-red-700'
    case 'unverified':
      return 'border-amber-300 bg-amber-50 text-amber-700'
    default:
      return 'border-gray-300 bg-gray-50 text-gray-600'
  }
}

interface AssumptionsEditorProps {
  threatModelId: string
  /** The blueprint new assumptions go to and whose rows are listed; null lists every blueprint. */
  blueprintId: number | null
}

export function AssumptionsEditor({ threatModelId, blueprintId }: AssumptionsEditorProps) {
  const { data: assumptions = [], isLoading } = useAssumptions(threatModelId, blueprintId ?? undefined)
  const { data: components = [] } = useAnalysisComponents(threatModelId)
  const createMutation = useCreateAssumption(threatModelId)
  const updateMutation = useUpdateAssumption(threatModelId)
  const deleteMutation = useDeleteAssumption(threatModelId)

  const [newDescription, setNewDescription] = useState('')
  const [newValidity, setNewValidity] = useState<AssumptionValidity>('unverified')
  const [isAdding, setIsAdding] = useState(false)

  const handleAdd = () => {
    const description = newDescription.trim()
    if (!description) return
    createMutation.mutate(
      { description, validity: newValidity, ...(blueprintId !== null ? { blueprint: blueprintId } : {}) },
      {
        onSuccess: () => {
          setNewDescription('')
          setNewValidity('unverified')
          setIsAdding(false)
        },
        onError: (error) => toast.error(error.message || 'Could not add the assumption'),
      }
    )
  }

  const handleUpdate = (assumptionId: number, data: UpdateAssumptionInput) => {
    updateMutation.mutate(
      { assumptionId, data },
      { onError: (error) => toast.error(error.message || 'Could not save the assumption') }
    )
  }

  const handleDelete = (assumptionId: number) => {
    deleteMutation.mutate(assumptionId, {
      onError: (error) => toast.error(error.message || 'Could not delete the assumption'),
    })
  }

  return (
    <div className="space-y-3" data-testid="assumptions-editor">
      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading assumptions
        </div>
      ) : assumptions.length === 0 ? (
        <div className="border rounded-md p-4 bg-muted/30 text-sm text-muted-foreground">
          No assumptions yet. An assumption is something the model takes as true until it is checked.
        </div>
      ) : (
        <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
          {assumptions.map((assumption) => (
            <AssumptionRow
              key={assumption.id}
              assumption={assumption}
              components={components.filter((component) => component.blueprint === assumption.blueprint)}
              onUpdate={(data) => handleUpdate(assumption.id, data)}
              onDelete={() => handleDelete(assumption.id)}
              isDeleting={deleteMutation.isPending && deleteMutation.variables === assumption.id}
            />
          ))}
        </div>
      )}

      {isAdding ? (
        <div className="border rounded-md p-3 space-y-2 bg-muted/50">
          <Label htmlFor="new-assumption" className="text-xs">
            New assumption
          </Label>
          <Textarea
            id="new-assumption"
            value={newDescription}
            onChange={(event) => setNewDescription(event.target.value)}
            placeholder="e.g. The control network has no direct internet route."
            rows={2}
            autoFocus
          />
          <div className="flex items-center justify-between gap-2">
            <Select value={newValidity} onValueChange={(value) => setNewValidity(value as AssumptionValidity)}>
              <SelectTrigger className="h-8 w-[150px] text-xs" aria-label="Validity">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ASSUMPTION_VALIDITY.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => setIsAdding(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                className="h-8 text-xs"
                onClick={handleAdd}
                disabled={!newDescription.trim() || createMutation.isPending}
              >
                {createMutation.isPending && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
                Add
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <Button variant="outline" className="w-full gap-2" onClick={() => setIsAdding(true)}>
          <Plus className="h-4 w-4" />
          Add assumption
        </Button>
      )}
    </div>
  )
}

interface AssumptionRowProps {
  assumption: Assumption
  components: OrgsystemComponent[]
  onUpdate: (data: UpdateAssumptionInput) => void
  onDelete: () => void
  isDeleting: boolean
}

type AssumptionTextField = 'description' | 'impact' | 'ownerName' | 'validationMethod'

function AssumptionRow({ assumption, components, onUpdate, onDelete, isDeleting }: AssumptionRowProps) {
  const [moreOpen, setMoreOpen] = useState(false)
  // A field's draft exists only while it is being edited; the row shows the
  // saved value otherwise, so a save elsewhere never overwrites typing here.
  const [drafts, setDrafts] = useState<Partial<Record<AssumptionTextField, string>>>({})

  const fieldValue = (field: AssumptionTextField): string => drafts[field] ?? assumption[field]
  const setFieldDraft = (field: AssumptionTextField, value: string) =>
    setDrafts((current) => ({ ...current, [field]: value }))
  const clearFieldDraft = (field: AssumptionTextField) =>
    setDrafts((current) => {
      const next = { ...current }
      delete next[field]
      return next
    })

  const description = fieldValue('description')
  const impact = fieldValue('impact')
  const ownerName = fieldValue('ownerName')
  const validationMethod = fieldValue('validationMethod')
  const setDescription = (value: string) => setFieldDraft('description', value)
  const setImpact = (value: string) => setFieldDraft('impact', value)
  const setOwnerName = (value: string) => setFieldDraft('ownerName', value)
  const setValidationMethod = (value: string) => setFieldDraft('validationMethod', value)

  const componentOptions = useMemo(
    () => components.map((component) => ({ value: String(component.id), label: component.name })),
    [components]
  )

  const saveText = (field: AssumptionTextField, value: string) => {
    const trimmed = value.trim()
    clearFieldDraft(field)
    if (field === 'description' && !trimmed) return
    if (trimmed === assumption[field]) return
    onUpdate({ [field]: trimmed })
  }

  return (
    <div className="border rounded-lg p-3 space-y-2" data-testid="assumption-row">
      <div className="flex items-start gap-2">
        <Textarea
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          onBlur={() => saveText('description', description)}
          rows={2}
          className="flex-1 text-sm min-h-0"
          aria-label="Assumption"
        />
        <Select
          value={assumption.validity}
          onValueChange={(value) => onUpdate({ validity: value as AssumptionValidity })}
        >
          <SelectTrigger
            className={cn('h-8 w-[130px] text-xs shrink-0', validityBadgeClass(assumption.validity))}
            aria-label="Validity"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ASSUMPTION_VALIDITY.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex items-center justify-between">
        <button
          type="button"
          className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
          onClick={() => setMoreOpen((open) => !open)}
          aria-expanded={moreOpen}
        >
          {moreOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          More
        </button>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1 px-2 text-xs text-muted-foreground hover:text-destructive"
          onClick={onDelete}
          disabled={isDeleting}
        >
          <Trash2 className="h-3 w-3" />
          Delete
        </Button>
      </div>
      {moreOpen && (
        <div className="grid grid-cols-2 gap-3 pt-1">
          <div className="space-y-1">
            <Label className="text-xs">Topic</Label>
            <Select
              value={assumption.topic || TOPIC_NONE}
              onValueChange={(value) => onUpdate({ topic: value === TOPIC_NONE ? '' : (value as AssumptionTopic) })}
            >
              <SelectTrigger className="h-8 text-xs" aria-label="Topic">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={TOPIC_NONE}>Not set</SelectItem>
                {ASSUMPTION_TOPICS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Owner</Label>
            <Input
              className="h-8 text-xs"
              value={ownerName}
              onChange={(event) => setOwnerName(event.target.value)}
              onBlur={() => saveText('ownerName', ownerName)}
              placeholder="Who owns this assumption"
            />
          </div>
          <div className="space-y-1 col-span-2">
            <Label className="text-xs">If this turns out false</Label>
            <Textarea
              value={impact}
              onChange={(event) => setImpact(event.target.value)}
              onBlur={() => saveText('impact', impact)}
              rows={2}
              className="text-xs"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">How it is checked</Label>
            <Input
              className="h-8 text-xs"
              value={validationMethod}
              onChange={(event) => setValidationMethod(event.target.value)}
              onBlur={() => saveText('validationMethod', validationMethod)}
              placeholder="e.g. Gate log audit"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Last checked</Label>
            <Input
              type="date"
              className="h-8 text-xs"
              value={assumption.validationDate ?? ''}
              onChange={(event) => onUpdate({ validationDate: event.target.value || null })}
            />
          </div>
          <div className="space-y-1 col-span-2">
            <Label className="text-xs">Related components</Label>
            <MultiSelectCombobox
              options={componentOptions}
              selected={assumption.componentIds.map(String)}
              onChange={(selected) => onUpdate({ componentIds: selected.map(Number) })}
              placeholder="Components of this blueprint"
              emptyMessage="No components in this blueprint"
            />
          </div>
        </div>
      )}
    </div>
  )
}
