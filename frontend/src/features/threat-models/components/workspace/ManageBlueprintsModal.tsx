/**
 * Manage blueprints (plan J2): add, rename, description, reorder, delete.
 * Name and model types are required and marked; a save with either missing
 * says so under the field. Delete is blocked for the last blueprint and
 * otherwise shows the `delete_preview` counts.
 */

import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Loader2, Pencil, Plus, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import { MODEL_TYPES, type ModelType } from '@/types/domain'
import {
  useBlueprintDeletePreview,
  useCreateBlueprint,
  useDeleteBlueprint,
  useUpdateBlueprint,
} from '@/features/threat-models/api/threat-models'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import { showDeleteWarnings } from '@/features/threat-models/api/delete-warnings'
import { useFlows } from '@/features/threat-models/api/flows'
import type { Blueprint } from '@/features/threat-models/types/core'
import {
  blueprintFormErrors,
  deletePreviewLines,
  nextDisplayOrder,
  reorderBlueprints,
  sortBlueprints,
  type BlueprintFormErrors,
} from './blueprint-utils'
import { apiErrorMessage } from './risk/risk-utils'

export type ManageBlueprintsMode = 'list' | 'add'

interface ManageBlueprintsModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  blueprints: Blueprint[]
  /** Open straight on the add form ("Add blueprint" in the menu). */
  initialMode?: ManageBlueprintsMode
  /** Called after a delete so the page can move its selection. */
  onDeleted?: (blueprintId: number) => void
}

export function ManageBlueprintsModal({
  open,
  onOpenChange,
  threatModelId,
  blueprints,
  initialMode = 'list',
  onDeleted,
}: ManageBlueprintsModalProps) {
  const deleteMutation = useDeleteBlueprint(threatModelId)
  const [blueprintToDelete, setBlueprintToDelete] = useState<Blueprint | null>(null)
  const { data: deletePreview, isLoading: isLoadingPreview } = useBlueprintDeletePreview(
    threatModelId,
    blueprintToDelete?.id ?? null
  )

  const handleDelete = () => {
    if (!blueprintToDelete) return
    const deletedId = blueprintToDelete.id
    deleteMutation.mutate(deletedId, {
      onSuccess: (warnings) => {
        toast.success(`Blueprint "${blueprintToDelete.name}" deleted`)
        showDeleteWarnings(warnings)
        setBlueprintToDelete(null)
        onDeleted?.(deletedId)
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not delete the blueprint'),
    })
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-2xl" data-testid="manage-blueprints">
          <DialogHeader>
            <DialogTitle>Manage blueprints</DialogTitle>
            <DialogDescription>
              A blueprint is one structural view of the system: its components, zones, flows and diagrams.
              Threats, controls and risks belong to the model, not to a blueprint.
            </DialogDescription>
          </DialogHeader>
          {/* The content unmounts when the dialog closes, so the body starts in `initialMode` on every open. */}
          <ManageBlueprintsBody
            threatModelId={threatModelId}
            blueprints={blueprints}
            initialMode={initialMode}
            onRequestDelete={setBlueprintToDelete}
          />
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!blueprintToDelete} onOpenChange={(isOpen) => !isOpen && setBlueprintToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{blueprintToDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2 text-sm text-muted-foreground">
                {isLoadingPreview ? (
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Checking what goes with it
                  </div>
                ) : deletePreview?.isLast ? (
                  <p>The last blueprint of a model cannot be deleted.</p>
                ) : deletePreview ? (
                  <>
                    {deletePreviewLines(deletePreview).length > 0 ? (
                      <>
                        <p>This will delete:</p>
                        <ul className="list-disc list-inside">
                          {deletePreviewLines(deletePreview).map((line) => (
                            <li key={line}>{line}</li>
                          ))}
                        </ul>
                      </>
                    ) : (
                      <p>The blueprint is empty.</p>
                    )}
                    <p>Threats whose other targets sit in another blueprint stay but lose those targets.</p>
                  </>
                ) : null}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleDelete()
              }}
              disabled={deleteMutation.isPending || isLoadingPreview || !!deletePreview?.isLast}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete blueprint'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

interface BlueprintFormState {
  name: string
  description: string
  modelTypes: string[]
  scopeDescription: string
}

// Model types start empty on purpose: the first blueprint is already a data
// flow model, and a new one is usually a different view (physical, process),
// so the user picks rather than accepting a default by accident.
const EMPTY_FORM: BlueprintFormState = { name: '', description: '', modelTypes: [], scopeDescription: '' }

interface ManageBlueprintsBodyProps {
  threatModelId: string
  blueprints: Blueprint[]
  initialMode: ManageBlueprintsMode
  onRequestDelete: (blueprint: Blueprint) => void
}

function ManageBlueprintsBody({ threatModelId, blueprints, initialMode, onRequestDelete }: ManageBlueprintsBodyProps) {
  const createMutation = useCreateBlueprint(threatModelId)
  const updateMutation = useUpdateBlueprint(threatModelId)
  const { data: components = [] } = useAnalysisComponents(threatModelId)
  const { data: flows = [] } = useFlows({ threatModel: threatModelId })

  const [editingId, setEditingId] = useState<number | null>(null)
  const [isAdding, setIsAdding] = useState(initialMode === 'add')
  const [form, setForm] = useState<BlueprintFormState>(EMPTY_FORM)
  // Shown after a save attempt; a field's message clears when it is edited.
  const [errors, setErrors] = useState<BlueprintFormErrors>({})

  const ordered = useMemo(() => sortBlueprints(blueprints), [blueprints])
  // A blueprint deleted while its form is open closes the form.
  const editingBlueprint = ordered.find((blueprint) => blueprint.id === editingId) ?? null

  const contentsByBlueprint = useMemo(() => {
    const counts = new Map<number, { components: number; flows: number }>()
    for (const blueprint of blueprints) counts.set(blueprint.id, { components: 0, flows: 0 })
    for (const component of components) {
      const entry = counts.get(component.blueprint)
      if (entry) entry.components += 1
    }
    for (const flow of flows) {
      const entry = counts.get(flow.blueprint)
      if (entry) entry.flows += 1
    }
    return counts
  }, [blueprints, components, flows])

  const resetForm = () => {
    setEditingId(null)
    setIsAdding(false)
    setForm(EMPTY_FORM)
    setErrors({})
  }

  const startAdd = () => {
    setEditingId(null)
    setForm(EMPTY_FORM)
    setErrors({})
    setIsAdding(true)
  }

  const startEdit = (blueprint: Blueprint) => {
    setIsAdding(false)
    setEditingId(blueprint.id)
    setForm({
      name: blueprint.name,
      description: blueprint.description,
      modelTypes: blueprint.modelTypes,
      scopeDescription: blueprint.scopeDescription,
    })
    setErrors({})
  }

  const handleSave = () => {
    const formErrors = blueprintFormErrors(form)
    setErrors(formErrors)
    if (Object.keys(formErrors).length > 0) return
    const trimmedName = form.name.trim()
    const data = {
      name: trimmedName,
      description: form.description.trim(),
      modelTypes: form.modelTypes as ModelType[],
      scopeDescription: form.scopeDescription.trim(),
    }
    const options = {
      onSuccess: () => resetForm(),
      onError: (error: Error) => toast.error(apiErrorMessage(error, 'Could not save the blueprint')),
    }
    if (editingBlueprint) {
      updateMutation.mutate({ blueprintId: editingBlueprint.id, data }, options)
    } else {
      createMutation.mutate({ ...data, displayOrder: nextDisplayOrder(blueprints) }, options)
    }
  }

  const handleReorder = (index: number, direction: 'up' | 'down') => {
    const updates = reorderBlueprints(blueprints, index, direction)
    for (const update of updates) {
      updateMutation.mutate({ blueprintId: update.blueprintId, data: { displayOrder: update.displayOrder } })
    }
  }

  const isSaving = createMutation.isPending || updateMutation.isPending
  const isLast = blueprints.length <= 1
  const showForm = isAdding || editingBlueprint !== null
  const modelTypeOptions = MODEL_TYPES.map((option) => ({ value: option.value, label: option.label }))

  return (
    <div className="space-y-4">
      <div className="border rounded-md divide-y">
        {ordered.map((blueprint, index) => {
          const contents = contentsByBlueprint.get(blueprint.id)
          return (
            <div key={blueprint.id} className="flex items-center justify-between gap-3 px-3 py-2" data-testid="blueprint-row">
              <div className="min-w-0">
                <div className="text-sm font-medium truncate">{blueprint.name}</div>
                <div className="text-xs text-muted-foreground">
                  {contents
                    ? `${contents.components} component${contents.components === 1 ? '' : 's'}, ${contents.flows} flow${
                        contents.flows === 1 ? '' : 's'
                      }`
                    : ''}
                  {blueprint.description ? ` · ${blueprint.description}` : ''}
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  disabled={index === 0 || updateMutation.isPending}
                  onClick={() => handleReorder(index, 'up')}
                  aria-label={`Move ${blueprint.name} up`}
                >
                  <ArrowUp className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  disabled={index === ordered.length - 1 || updateMutation.isPending}
                  onClick={() => handleReorder(index, 'down')}
                  aria-label={`Move ${blueprint.name} down`}
                >
                  <ArrowDown className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={() => startEdit(blueprint)}>
                  <Pencil className="h-3 w-3" />
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs text-muted-foreground hover:text-destructive"
                  onClick={() => onRequestDelete(blueprint)}
                  disabled={isLast}
                  title={isLast ? 'The last blueprint of a model cannot be deleted' : undefined}
                >
                  <Trash2 className="h-3 w-3" />
                  Delete
                </Button>
              </div>
            </div>
          )
        })}
        {ordered.length === 0 && (
          <div className="px-3 py-6 text-center text-sm text-muted-foreground">No blueprints yet</div>
        )}
      </div>

      {showForm ? (
        <div className="border rounded-md p-4 space-y-3 bg-muted/50">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">
              {editingBlueprint ? `Edit "${editingBlueprint.name}"` : 'New blueprint'}
            </span>
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={resetForm} aria-label="Close form">
              <X className="h-4 w-4" />
            </Button>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="blueprint-name" className="text-xs">
              Name *
            </Label>
            <Input
              id="blueprint-name"
              value={form.name}
              onChange={(event) => {
                setForm((current) => ({ ...current, name: event.target.value }))
                setErrors((current) => ({ ...current, name: undefined }))
              }}
              placeholder="e.g. Plant network view"
              aria-invalid={Boolean(errors.name)}
              autoFocus
            />
            {errors.name && <p className="text-xs text-destructive">{errors.name}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="blueprint-description" className="text-xs">
              Description
            </Label>
            <Textarea
              id="blueprint-description"
              value={form.description}
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              rows={2}
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Model types *</Label>
            <MultiSelectCombobox
              options={modelTypeOptions}
              selected={form.modelTypes}
              onChange={(selected) => {
                setForm((current) => ({ ...current, modelTypes: selected }))
                setErrors((current) => ({ ...current, modelTypes: undefined }))
              }}
              placeholder="Choose model types"
            />
            {errors.modelTypes && <p className="text-xs text-destructive">{errors.modelTypes}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="blueprint-scope" className="text-xs">
              Scope description
            </Label>
            <Textarea
              id="blueprint-scope"
              value={form.scopeDescription}
              onChange={(event) => setForm((current) => ({ ...current, scopeDescription: event.target.value }))}
              rows={2}
            />
          </div>
          <div className="flex justify-end">
            <Button size="sm" onClick={handleSave} disabled={isSaving}>
              {isSaving && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
              {editingBlueprint ? 'Save' : 'Add blueprint'}
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="outline" className="w-full gap-2" onClick={startAdd}>
          <Plus className="h-4 w-4" />
          Add blueprint
        </Button>
      )}
    </div>
  )
}
