/**
 * Out-of-scope items of a model. Each item belongs to a blueprint (plan
 * J8): with more than one blueprint the form shows a blueprint select
 * preset to the switcher's blueprint and the list is grouped by blueprint;
 * with one blueprint nothing of this is visible.
 */

import { useState } from 'react'
import { Plus, Trash2, Pencil, X, Check, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import {
  useOutOfScopeItems,
  useCreateOutOfScopeItem,
  useUpdateOutOfScopeItem,
  useDeleteOutOfScopeItem,
  type OutOfScopeItem,
} from '@/features/threat-models/api/out-of-scope-items'
import type { Blueprint } from '@/features/threat-models/types/core'
import { groupByBlueprint, resolveSelectedBlueprintId, showsBlueprintChoice, sortBlueprints } from './blueprint-utils'

interface OutOfScopeModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  blueprints: Blueprint[]
  /** The switcher's blueprint; new items go there unless the form says otherwise. */
  selectedBlueprintId: number | null
}

export function OutOfScopeModal({
  open,
  onOpenChange,
  threatModelId,
  blueprints,
  selectedBlueprintId,
}: OutOfScopeModalProps) {
  const { data: items = [], isLoading } = useOutOfScopeItems(threatModelId)
  const createItemMutation = useCreateOutOfScopeItem()
  const updateItemMutation = useUpdateOutOfScopeItem()
  const deleteItemMutation = useDeleteOutOfScopeItem()

  const [editingId, setEditingId] = useState<number | null>(null)
  const [isAdding, setIsAdding] = useState(false)

  // Form state for add/edit
  const [formName, setFormName] = useState('')
  const [formReason, setFormReason] = useState('')
  // Null means "the switcher's blueprint"; set when the user picks another or edits a row.
  const [formBlueprintChoice, setFormBlueprintChoice] = useState<number | null>(null)
  const formBlueprintId = formBlueprintChoice ?? resolveSelectedBlueprintId(selectedBlueprintId, blueprints)
  const setFormBlueprintId = setFormBlueprintChoice

  const showBlueprintChoice = showsBlueprintChoice(blueprints)

  const resetForm = () => {
    setFormName('')
    setFormReason('')
    setFormBlueprintChoice(null)
    setEditingId(null)
    setIsAdding(false)
  }

  const handleStartAdd = () => {
    resetForm()
    setIsAdding(true)
  }

  const handleStartEdit = (item: OutOfScopeItem) => {
    setFormName(item.name)
    setFormReason(item.reason)
    setFormBlueprintChoice(item.blueprint ?? null)
    setEditingId(item.id)
    setIsAdding(false)
  }

  const handleSaveItem = () => {
    if (!formName.trim()) return
    const blueprint = formBlueprintId ?? undefined

    if (editingId) {
      updateItemMutation.mutate(
        {
          threatModelId,
          id: editingId,
          data: {
            name: formName.trim(),
            reason: formReason.trim(),
            ...(blueprint !== undefined ? { blueprint } : {}),
          },
        },
        { onSuccess: () => resetForm() }
      )
    } else {
      createItemMutation.mutate(
        {
          threatModelId,
          data: {
            name: formName.trim(),
            reason: formReason.trim(),
            ...(blueprint !== undefined ? { blueprint } : {}),
          },
        },
        { onSuccess: () => resetForm() }
      )
    }
  }

  const handleDelete = (id: number) => {
    deleteItemMutation.mutate({ threatModelId, id })
    if (editingId === id) {
      resetForm()
    }
  }

  const isSaving = createItemMutation.isPending || updateItemMutation.isPending

  const renderItem = (item: OutOfScopeItem) => (
    <div
      key={item.id}
      className={cn('flex items-start justify-between p-3 rounded', editingId === item.id ? 'bg-muted' : 'hover:bg-muted')}
      data-testid="out-of-scope-row"
    >
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium">{item.name}</div>
        {item.reason && (
          <div className="text-xs text-muted-foreground mt-1">
            <span className="font-medium">Reason:</span> {item.reason}
          </div>
        )}
      </div>
      <div className="flex items-center gap-1 ml-2">
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleStartEdit(item)}>
          <Pencil className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:text-destructive"
          onClick={() => handleDelete(item.id)}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Out of scope</DialogTitle>
          <DialogDescription>
            Components, systems or areas that are explicitly excluded from this threat model.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Items list */}
          <ScrollArea className="h-[250px] border rounded-md">
            <div className="p-2 space-y-1">
              {isLoading ? (
                <div className="p-8 text-center">
                  <Loader2 className="h-5 w-5 animate-spin mx-auto text-muted-foreground" />
                </div>
              ) : items.length === 0 ? (
                <div className="p-8 text-center text-sm text-muted-foreground">No out of scope items defined yet</div>
              ) : showBlueprintChoice ? (
                groupByBlueprint(items, blueprints).map((group) => (
                  <div key={group.blueprint?.id ?? 'unassigned'} className="space-y-1">
                    <div className="px-3 pt-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      {group.blueprint?.name ?? 'No blueprint'}
                    </div>
                    {group.items.map(renderItem)}
                  </div>
                ))
              ) : (
                items.map(renderItem)
              )}
            </div>
          </ScrollArea>

          {/* Add/Edit form */}
          {(isAdding || editingId) && (
            <div className="border rounded-md p-4 space-y-3 bg-muted/50">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{editingId ? 'Edit item' : 'New item'}</span>
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={resetForm}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <div className="space-y-3">
                {showBlueprintChoice && (
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium">Blueprint</label>
                    <Select
                      value={formBlueprintId !== null ? String(formBlueprintId) : ''}
                      onValueChange={(value) => setFormBlueprintId(Number(value))}
                    >
                      <SelectTrigger className="h-8 text-sm" aria-label="Blueprint">
                        <SelectValue placeholder="Choose a blueprint" />
                      </SelectTrigger>
                      <SelectContent>
                        {sortBlueprints(blueprints).map((blueprint) => (
                          <SelectItem key={blueprint.id} value={String(blueprint.id)}>
                            {blueprint.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Name</label>
                  <Input
                    placeholder="e.g., Legacy Payment Gateway"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Reason for exclusion</label>
                  <Textarea
                    placeholder="Explain why this is out of scope..."
                    value={formReason}
                    onChange={(e) => setFormReason(e.target.value)}
                    rows={2}
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <Button size="sm" onClick={handleSaveItem} disabled={!formName.trim() || isSaving} className="gap-1">
                  {isSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
                  {editingId ? 'Update' : 'Add'}
                </Button>
              </div>
            </div>
          )}

          {/* Add button */}
          {!isAdding && !editingId && (
            <Button variant="outline" onClick={handleStartAdd} className="w-full gap-2">
              <Plus className="h-4 w-4" />
              Add out of scope item
            </Button>
          )}

          {/* Actions */}
          <div className="flex justify-end pt-2 border-t">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
