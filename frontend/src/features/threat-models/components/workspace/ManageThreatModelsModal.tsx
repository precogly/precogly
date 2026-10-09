/**
 * Related models (plan J15): link another model with a relationship type
 * worded from this model's side ("depends on", "is a subsystem of",
 * "is related to", "is superseded by"). The backend refuses a self link and
 * a loop of "is a subsystem of" or "is superseded by"; its message is shown.
 */

import { useState } from 'react'
import { ArrowLeft, ArrowRight, Loader2, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { DEFAULT_RELATION_TYPE, RELATION_TYPES, type RelationType } from '@/types/domain'
import type { RelatedModel, ThreatModel } from '@/features/threat-models/types/core'
import { relationSentence } from './relation-utils'

interface ManageThreatModelsModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Every relationship this model takes part in, with type and direction. */
  relatedModels: RelatedModel[]
  availableModels: ThreatModel[]
  currentModelId: string
  /** Resolves on success; rejects with the backend's message (loop, self link). */
  onAdd: (targetModelId: number, relationType: RelationType) => Promise<void>
  onRemove: (targetModelId: number, relationType: RelationType) => void
  isAdding?: boolean
}

export function ManageThreatModelsModal({
  open,
  onOpenChange,
  relatedModels,
  availableModels,
  currentModelId,
  onAdd,
  onRemove,
  isAdding = false,
}: ManageThreatModelsModalProps) {
  const [relationType, setRelationType] = useState<RelationType>(DEFAULT_RELATION_TYPE)
  const [targetModelId, setTargetModelId] = useState<string>('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const choosableModels = availableModels.filter((model) => String(model.id) !== currentModelId)

  const handleAdd = async () => {
    if (!targetModelId) return
    setErrorMessage(null)
    try {
      await onAdd(Number(targetModelId), relationType)
      setTargetModelId('')
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not link the model')
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Related models</DialogTitle>
          <DialogDescription>Link this model to others and say how they relate.</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div>
            <h4 className="text-sm font-medium mb-2">Relationships</h4>
            <ScrollArea className="h-[160px] border rounded-md">
              <div className="p-2 space-y-1">
                {relatedModels.length > 0 ? (
                  relatedModels.map((relationship) => (
                    <div
                      key={relationship.id}
                      className="flex items-center justify-between gap-2 p-2 hover:bg-muted rounded"
                      data-testid="related-model-row"
                    >
                      <div className="flex items-center gap-2 min-w-0 text-sm">
                        {relationship.direction === 'outgoing' ? (
                          <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        ) : (
                          <ArrowLeft className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        )}
                        <span className="truncate">{relationSentence(relationship)}</span>
                      </div>
                      {relationship.direction === 'outgoing' ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-muted-foreground hover:text-destructive shrink-0"
                          onClick={() => onRemove(relationship.model.id, relationship.relationType)}
                          aria-label={`Remove link to ${relationship.model.name}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground shrink-0">Set on the other model</span>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="p-4 text-center text-sm text-muted-foreground">No related models</div>
                )}
              </div>
            </ScrollArea>
          </div>

          <div className="space-y-3">
            <h4 className="text-sm font-medium">Add a relationship</h4>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs" htmlFor="relation-type">
                  Relationship
                </Label>
                <Select value={relationType} onValueChange={(value) => setRelationType(value as RelationType)}>
                  <SelectTrigger id="relation-type" className="h-8 text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RELATION_TYPES.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        This model {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs" htmlFor="relation-target">
                  Model
                </Label>
                <Select value={targetModelId} onValueChange={setTargetModelId}>
                  <SelectTrigger id="relation-target" className="h-8 text-sm">
                    <SelectValue placeholder="Choose a model" />
                  </SelectTrigger>
                  <SelectContent>
                    {choosableModels.length === 0 ? (
                      <div className="px-2 py-1.5 text-xs text-muted-foreground">No other models</div>
                    ) : (
                      choosableModels.map((model) => (
                        <SelectItem key={model.id} value={String(model.id)}>
                          {model.name}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {errorMessage && (
              <Alert variant="destructive">
                <AlertDescription className="text-xs">{errorMessage}</AlertDescription>
              </Alert>
            )}
            <div className="flex justify-end">
              <Button size="sm" onClick={handleAdd} disabled={!targetModelId || isAdding} className="gap-1">
                {isAdding ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                Add
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
