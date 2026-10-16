/** Create or edit an abuse case. Threats are linked in the threat analysis view, not here. */

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ActorPicker } from '@/features/dfd-editor/components/threat-analysis/ActorPicker'
import {
  useCreateAbuseCase,
  useUpdateAbuseCase,
  useUseCases,
} from '@/features/threat-models/api/threat-models'
import { useThreatPersonas } from '@/features/threat-models/api/threats'
import type { AbuseCase } from '@/features/threat-models/types/core'
import { ComponentFlowPicker } from './ComponentFlowPicker'
import { FlowStepsEditor } from './FlowStepsEditor'
import { ABUSE_CASE_EXAMPLES, ABUSE_CASE_HELP } from './use-case-examples'
import { StringListEditor } from './StringListEditor'
import { initialAbuseCaseForm, buildAbuseCaseInput, errorMessages, type AbuseCaseFormState } from './use-case-utils'


interface AbuseCaseDialogProps {
  threatModelId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this abuse case; omit to create. */
  abuseCase?: AbuseCase
  /** Use case to link a new abuse case to (the "+ Abuse case" action under a use case). */
  defaultUseCaseId?: number
  onSaved?: (abuseCase: AbuseCase) => void
}

export function AbuseCaseDialog({
  threatModelId,
  open,
  onOpenChange,
  abuseCase,
  defaultUseCaseId,
  onSaved,
}: AbuseCaseDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{abuseCase ? 'Edit abuse case' : 'Add abuse case'}</DialogTitle>
          <DialogDescription>{ABUSE_CASE_HELP} Only the name is required.</DialogDescription>
        </DialogHeader>
        <AbuseCaseForm
          key={abuseCase?.id ?? 'new'}
          threatModelId={threatModelId}
          abuseCase={abuseCase}
          defaultUseCaseId={defaultUseCaseId}
          onClose={() => onOpenChange(false)}
          onSaved={onSaved}
        />
      </DialogContent>
    </Dialog>
  )
}

interface AbuseCaseFormProps {
  threatModelId: string
  abuseCase?: AbuseCase
  defaultUseCaseId?: number
  onClose: () => void
  onSaved?: (abuseCase: AbuseCase) => void
}

function AbuseCaseForm({ threatModelId, abuseCase, defaultUseCaseId, onClose, onSaved }: AbuseCaseFormProps) {
  const createMutation = useCreateAbuseCase(threatModelId)
  const updateMutation = useUpdateAbuseCase(threatModelId)
  const { data: useCases = [] } = useUseCases(threatModelId)
  const { data: personas = [] } = useThreatPersonas(threatModelId)
  const isSaving = createMutation.isPending || updateMutation.isPending

  const [form, setForm] = useState<AbuseCaseFormState>(() => initialAbuseCaseForm(abuseCase, defaultUseCaseId))
  const [errors, setErrors] = useState<string[]>([])

  const patch = (changes: Partial<AbuseCaseFormState>) => setForm((current) => ({ ...current, ...changes }))

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!form.name.trim()) return
    setErrors([])
    const data = buildAbuseCaseInput(form)
    const options = {
      onSuccess: (saved: AbuseCase) => {
        toast.success(abuseCase ? 'Abuse case saved' : 'Abuse case added')
        onSaved?.(saved)
        onClose()
      },
      onError: (error: Error) => setErrors(errorMessages(error, 'Could not save the abuse case')),
    }
    if (abuseCase) {
      updateMutation.mutate({ abuseCaseId: abuseCase.id, data }, options)
    } else {
      createMutation.mutate(data, options)
    }
  }

  const mitigations = abuseCase?.mitigations ?? []

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="abuse-case-name">Name</Label>
        <Input
          id="abuse-case-name"
          value={form.name}
          onChange={(event) => patch({ name: event.target.value })}
          placeholder={ABUSE_CASE_EXAMPLES.name}
          autoFocus
          required
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="abuse-case-description">Description</Label>
        <Textarea
          id="abuse-case-description"
          value={form.description}
          onChange={(event) => patch({ description: event.target.value })}
          placeholder={ABUSE_CASE_EXAMPLES.description}
          rows={3}
        />
      </div>

      <div className="space-y-1.5">
        {/* The spec's `abuser`: the same threat actor list as a threat's, minus free text. */}
        <Label htmlFor="abuse-case-abuser">Threat actor</Label>
        <ActorPicker
          id="abuse-case-abuser"
          threatModelId={threatModelId}
          personas={personas}
          value={{ actorPersona: form.abuserId, threatActorText: '' }}
          onChange={(actor) => patch({ abuserId: actor.actorPersona })}
          allowCustomText={false}
        />
      </div>

      <div className="space-y-1.5">
        <Label>Use cases</Label>
        <MultiSelectCombobox
          options={useCases.map((useCase) => ({ value: String(useCase.id), label: useCase.name }))}
          selected={form.useCaseIds.map(String)}
          onChange={(selected) => patch({ useCaseIds: selected.map(Number) })}
          placeholder="Add a use case"
          searchPlaceholder="Search use cases"
          emptyMessage="No use case matches"
        />
      </div>

      <ComponentFlowPicker
        threatModelId={threatModelId}
        componentIds={form.componentIds}
        flowIds={form.flowIds}
        onChange={(selection) => patch(selection)}
      />

      <StringListEditor
        label="Preconditions"
        rows={form.preconditions}
        onChange={(preconditions) => patch({ preconditions })}
        addLabel="Add precondition"
        placeholders={ABUSE_CASE_EXAMPLES.preconditions}
      />
      <FlowStepsEditor
        label="Main flow"
        steps={form.mainFlow}
        onChange={(mainFlow) => patch({ mainFlow })}
        placeholders={ABUSE_CASE_EXAMPLES.mainFlow}
      />
      <StringListEditor
        label="Detection opportunities"
        rows={form.detectionOpportunities}
        onChange={(detectionOpportunities) => patch({ detectionOpportunities })}
        addLabel="Add detection opportunity"
        placeholders={ABUSE_CASE_EXAMPLES.detectionOpportunities}
      />

      {mitigations.length > 0 && (
        <div className="space-y-1" data-testid="abuse-case-mitigations">
          <div className="text-sm font-medium">Controls named by the imported file</div>
          <p className="text-sm text-muted-foreground">
            {mitigations.map((mitigation) => `${mitigation.displayNumber} ${mitigation.name}`).join(', ')}
          </p>
        </div>
      )}

      {errors.length > 0 && (
        <ul className="space-y-0.5 text-sm text-destructive" role="alert" data-testid="abuse-case-errors">
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
          {abuseCase ? 'Save' : 'Add abuse case'}
        </Button>
      </DialogFooter>
    </form>
  )
}
