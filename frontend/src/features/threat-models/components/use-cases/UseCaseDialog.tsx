/** Create or edit a use case. Everything except the name is optional. */

import { useState } from 'react'
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import {
  useBusinessObjectives,
  useCreateUseCase,
  useUpdateUseCase,
} from '@/features/threat-models/api/threat-models'
import type { UseCase } from '@/features/threat-models/types/core'
import { AlternativeFlowsEditor, ExceptionsEditor } from './AlternativeFlowsEditor'
import { ComponentFlowPicker } from './ComponentFlowPicker'
import { FlowStepsEditor } from './FlowStepsEditor'
import { USE_CASE_EXAMPLES } from './use-case-examples'
import { StringListEditor } from './StringListEditor'
import { buildUseCaseInput, errorMessages, initialUseCaseForm, type UseCaseFormState } from './use-case-utils'

interface UseCaseDialogProps {
  threatModelId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this use case; omit to create. */
  useCase?: UseCase
  onSaved?: (useCase: UseCase) => void
}

export function UseCaseDialog({ threatModelId, open, onOpenChange, useCase, onSaved }: UseCaseDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{useCase ? 'Edit use case' : 'Add use case'}</DialogTitle>
          <DialogDescription>What the system is for, step by step, from the user's side. Only the name is required.</DialogDescription>
        </DialogHeader>
        {/* The content unmounts when the dialog closes, so the form starts fresh on every open. */}
        <UseCaseForm
          key={useCase?.id ?? 'new'}
          threatModelId={threatModelId}
          useCase={useCase}
          onClose={() => onOpenChange(false)}
          onSaved={onSaved}
        />
      </DialogContent>
    </Dialog>
  )
}

interface UseCaseFormProps {
  threatModelId: string
  useCase?: UseCase
  onClose: () => void
  onSaved?: (useCase: UseCase) => void
}

function UseCaseForm({ threatModelId, useCase, onClose, onSaved }: UseCaseFormProps) {
  const createMutation = useCreateUseCase(threatModelId)
  const updateMutation = useUpdateUseCase(threatModelId)
  const { data: objectives = [] } = useBusinessObjectives(threatModelId)
  const isSaving = createMutation.isPending || updateMutation.isPending

  const [form, setForm] = useState<UseCaseFormState>(() => initialUseCaseForm(useCase))
  const [showMore, setShowMore] = useState(
    () => (form.alternativeFlows.length > 0 || form.exceptions.length > 0)
  )
  const [errors, setErrors] = useState<string[]>([])

  const patch = (changes: Partial<UseCaseFormState>) => setForm((current) => ({ ...current, ...changes }))

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!form.name.trim()) return
    setErrors([])
    const data = buildUseCaseInput(form, objectives.length > 0)
    const options = {
      onSuccess: (saved: UseCase) => {
        toast.success(useCase ? 'Use case saved' : 'Use case added')
        onSaved?.(saved)
        onClose()
      },
      onError: (error: Error) => setErrors(errorMessages(error, 'Could not save the use case')),
    }
    if (useCase) {
      updateMutation.mutate({ useCaseId: useCase.id, data }, options)
    } else {
      createMutation.mutate(data, options)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="use-case-name">Name</Label>
        <Input
          id="use-case-name"
          value={form.name}
          onChange={(event) => patch({ name: event.target.value })}
          placeholder={USE_CASE_EXAMPLES.name}
          autoFocus
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="use-case-description">Description</Label>
        <Textarea
          id="use-case-description"
          value={form.description}
          onChange={(event) => patch({ description: event.target.value })}
          placeholder={USE_CASE_EXAMPLES.description}
          rows={3}
        />
      </div>

      <ComponentFlowPicker
        threatModelId={threatModelId}
        componentIds={form.componentIds}
        flowIds={form.flowIds}
        onChange={(selection) => patch(selection)}
      />

      {objectives.length > 0 && (
        <div className="space-y-1.5">
          <Label>Business objectives</Label>
          <MultiSelectCombobox
            options={objectives.map((objective) => ({
              value: String(objective.id),
              label: objective.name,
              meta: objective.criticality || undefined,
            }))}
            selected={form.businessObjectiveIds.map(String)}
            onChange={(selected) => patch({ businessObjectiveIds: selected.map(Number) })}
            placeholder="Add an objective"
            searchPlaceholder="Search objectives"
            emptyMessage="No objective matches"
          />
        </div>
      )}

      <FlowStepsEditor
        label="Main flow"
        steps={form.mainFlow}
        onChange={(mainFlow) => patch({ mainFlow })}
        placeholders={USE_CASE_EXAMPLES.mainFlow}
      />
      <StringListEditor
        label="Preconditions"
        rows={form.preconditions}
        onChange={(preconditions) => patch({ preconditions })}
        addLabel="Add precondition"
        placeholders={USE_CASE_EXAMPLES.preconditions}
      />
      <StringListEditor
        label="Postconditions"
        rows={form.postconditions}
        onChange={(postconditions) => patch({ postconditions })}
        addLabel="Add postcondition"
        placeholders={USE_CASE_EXAMPLES.postconditions}
      />
      <StringListEditor
        label="Success criteria"
        rows={form.successCriteria}
        onChange={(successCriteria) => patch({ successCriteria })}
        addLabel="Add criterion"
        placeholders={USE_CASE_EXAMPLES.successCriteria}
      />

      <div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 gap-1 px-2 text-xs"
          onClick={() => setShowMore((current) => !current)}
          aria-expanded={showMore}
        >
          {showMore ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          More
        </Button>
        {showMore && (
          <div className="mt-2 space-y-4">
            <AlternativeFlowsEditor flows={form.alternativeFlows} onChange={(alternativeFlows) => patch({ alternativeFlows })} />
            <ExceptionsEditor exceptions={form.exceptions} onChange={(exceptions) => patch({ exceptions })} />
          </div>
        )}
      </div>

      {errors.length > 0 && (
        <ul className="space-y-0.5 text-sm text-destructive" role="alert" data-testid="use-case-errors">
          {errors.map((message, index) => (
            <li key={index}>{message}</li>
          ))}
        </ul>
      )}

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={isSaving}>
          Cancel
        </Button>
        <Button type="submit" disabled={!form.name.trim() || isSaving}>
          {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {useCase ? 'Save' : 'Add use case'}
        </Button>
      </DialogFooter>
    </form>
  )
}
