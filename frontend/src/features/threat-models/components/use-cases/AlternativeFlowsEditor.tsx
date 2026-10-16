/** Alternative flows and exceptions of a use case (the collapsed "More" section). */

import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import type { AlternativeFlow, UseCaseException } from '@/features/threat-models/types/core'
import { FlowStepsEditor } from './FlowStepsEditor'
import { USE_CASE_EXAMPLES } from './use-case-examples'

interface AlternativeFlowsEditorProps {
  flows: AlternativeFlow[]
  onChange: (flows: AlternativeFlow[]) => void
}

export function AlternativeFlowsEditor({ flows, onChange }: AlternativeFlowsEditorProps) {
  const update = (index: number, patch: Partial<AlternativeFlow>) =>
    onChange(flows.map((flow, flowIndex) => (flowIndex === index ? { ...flow, ...patch } : flow)))

  return (
    <div className="space-y-2" data-testid="alternative-flows-editor">
      <div className="text-sm font-medium">Alternative flows</div>
      {flows.map((flow, index) => (
        <div key={index} className="space-y-2 rounded-md border p-2">
          <div className="flex items-center gap-1.5">
            <Input
              value={flow.name}
              onChange={(event) => update(index, { name: event.target.value })}
              placeholder={USE_CASE_EXAMPLES.alternativeFlow.name}
              aria-label={`Alternative flow ${index + 1} name`}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => onChange(flows.filter((_, flowIndex) => flowIndex !== index))}
              aria-label={`Remove alternative flow ${index + 1}`}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
          <Input
            value={flow.condition}
            onChange={(event) => update(index, { condition: event.target.value })}
            placeholder={USE_CASE_EXAMPLES.alternativeFlow.condition}
            aria-label={`Alternative flow ${index + 1} condition`}
          />
          <Input
            value={flow.description ?? ''}
            onChange={(event) => update(index, { description: event.target.value })}
            placeholder={USE_CASE_EXAMPLES.alternativeFlow.description}
            aria-label={`Alternative flow ${index + 1} description`}
          />
          <FlowStepsEditor
            label="Steps"
            steps={flow.steps ?? []}
            onChange={(steps) => update(index, { steps })}
            placeholders={USE_CASE_EXAMPLES.alternativeFlow.steps}
          />
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 gap-1 px-2 text-xs"
        onClick={() => onChange([...flows, { name: '', condition: '' }])}
      >
        <Plus className="h-3 w-3" />
        Add alternative flow
      </Button>
    </div>
  )
}

interface ExceptionsEditorProps {
  exceptions: UseCaseException[]
  onChange: (exceptions: UseCaseException[]) => void
}

export function ExceptionsEditor({ exceptions, onChange }: ExceptionsEditorProps) {
  const update = (index: number, patch: Partial<UseCaseException>) =>
    onChange(exceptions.map((exception, exceptionIndex) => (exceptionIndex === index ? { ...exception, ...patch } : exception)))

  return (
    <div className="space-y-2" data-testid="exceptions-editor">
      <div className="text-sm font-medium">Exceptions</div>
      {exceptions.map((exception, index) => (
        <div key={index} className="space-y-2 rounded-md border p-2">
          <div className="flex items-center gap-1.5">
            <Input
              value={exception.name}
              onChange={(event) => update(index, { name: event.target.value })}
              placeholder={USE_CASE_EXAMPLES.exception.name}
              aria-label={`Exception ${index + 1} name`}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => onChange(exceptions.filter((_, exceptionIndex) => exceptionIndex !== index))}
              aria-label={`Remove exception ${index + 1}`}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
          <Input
            value={exception.condition}
            onChange={(event) => update(index, { condition: event.target.value })}
            placeholder={USE_CASE_EXAMPLES.exception.condition}
            aria-label={`Exception ${index + 1} condition`}
          />
          <Input
            value={exception.description ?? ''}
            onChange={(event) => update(index, { description: event.target.value })}
            placeholder={USE_CASE_EXAMPLES.exception.description}
            aria-label={`Exception ${index + 1} description`}
          />
          <Textarea
            value={exception.handling ?? ''}
            onChange={(event) => update(index, { handling: event.target.value })}
            placeholder={USE_CASE_EXAMPLES.exception.handling}
            aria-label={`Exception ${index + 1} handling`}
            rows={2}
          />
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 gap-1 px-2 text-xs"
        onClick={() => onChange([...exceptions, { name: '', condition: '' }])}
      >
        <Plus className="h-3 w-3" />
        Add exception
      </Button>
    </div>
  )
}
