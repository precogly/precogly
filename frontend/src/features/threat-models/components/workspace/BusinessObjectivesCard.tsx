/**
 * Business objectives of a model (plan 11.5): a small table with name,
 * criticality, owner and the threat and risk counts, plus an edit dialog.
 * Once one objective exists, threats and risks get a picker for them.
 */

import { useState } from 'react'
import { Loader2, Pencil, Plus, Target, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { BUSINESS_OBJECTIVE_CRITICALITIES, type BusinessObjectiveCriticality } from '@/types/domain'
import {
  useBusinessObjectives,
  useCreateBusinessObjective,
  useDeleteBusinessObjective,
  useUpdateBusinessObjective,
} from '@/features/threat-models/api/threat-models'
import type { BusinessObjective } from '@/features/threat-models/types/core'

const CRITICALITY_NONE = 'none'

function criticalityLabel(value: BusinessObjectiveCriticality | ''): string {
  if (!value) return ''
  return BUSINESS_OBJECTIVE_CRITICALITIES.find((option) => option.value === value)?.label ?? value
}

interface BusinessObjectivesCardProps {
  threatModelId: string
}

export function BusinessObjectivesCard({ threatModelId }: BusinessObjectivesCardProps) {
  const { data: objectives = [], isLoading } = useBusinessObjectives(threatModelId)
  const deleteMutation = useDeleteBusinessObjective(threatModelId)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingObjective, setEditingObjective] = useState<BusinessObjective | null>(null)
  const [objectiveToDelete, setObjectiveToDelete] = useState<BusinessObjective | null>(null)

  const openCreate = () => {
    setEditingObjective(null)
    setDialogOpen(true)
  }

  const openEdit = (objective: BusinessObjective) => {
    setEditingObjective(objective)
    setDialogOpen(true)
  }

  const handleDelete = () => {
    if (!objectiveToDelete) return
    deleteMutation.mutate(objectiveToDelete.id, {
      onSuccess: () => {
        toast.success('Objective deleted')
        setObjectiveToDelete(null)
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not delete the objective'),
    })
  }

  return (
    <Card data-testid="business-objectives-card">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Target className="h-4 w-4 text-muted-foreground" />
            Business objectives
          </CardTitle>
          <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={openCreate}>
            <Plus className="h-3 w-3" />
            Add objective
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading objectives
          </div>
        ) : objectives.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No business objectives yet. Once one exists, threats and risks can be linked to it.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Objective</TableHead>
                <TableHead className="text-xs">Criticality</TableHead>
                <TableHead className="text-xs">Owner</TableHead>
                <TableHead className="text-xs text-right">Threats</TableHead>
                <TableHead className="text-xs text-right">Risks</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {objectives.map((objective) => (
                <TableRow key={objective.id} data-testid="business-objective-row">
                  <TableCell className="text-sm">
                    <div className="font-medium">{objective.name}</div>
                    {objective.description && (
                      <div className="text-xs text-muted-foreground line-clamp-2">{objective.description}</div>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{criticalityLabel(objective.criticality)}</TableCell>
                  <TableCell className="text-sm">{objective.ownerName || objective.ownerEmail || ''}</TableCell>
                  <TableCell className="text-sm text-right tabular-nums">{objective.threatCount}</TableCell>
                  <TableCell className="text-sm text-right tabular-nums">{objective.riskCount}</TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => openEdit(objective)}
                        aria-label={`Edit ${objective.name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        onClick={() => setObjectiveToDelete(objective)}
                        aria-label={`Delete ${objective.name}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <BusinessObjectiveDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        threatModelId={threatModelId}
        objective={editingObjective}
      />

      <AlertDialog open={!!objectiveToDelete} onOpenChange={(open) => !open && setObjectiveToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{objectiveToDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              {objectiveToDelete && (objectiveToDelete.threatCount > 0 || objectiveToDelete.riskCount > 0)
                ? `${objectiveToDelete.threatCount} threat${objectiveToDelete.threatCount === 1 ? '' : 's'} and ${
                    objectiveToDelete.riskCount
                  } risk${objectiveToDelete.riskCount === 1 ? '' : 's'} lose this objective. They are not deleted.`
                : 'Nothing links to this objective.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleDelete()
              }}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

interface BusinessObjectiveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  objective: BusinessObjective | null
}

function BusinessObjectiveDialog({ open, onOpenChange, threatModelId, objective }: BusinessObjectiveDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{objective ? 'Edit objective' : 'Add objective'}</DialogTitle>
          <DialogDescription>What the business needs from this system.</DialogDescription>
        </DialogHeader>
        {/* The content unmounts when the dialog closes, so the form starts fresh on every open. */}
        <BusinessObjectiveForm
          key={objective?.id ?? 'new'}
          threatModelId={threatModelId}
          objective={objective}
          onClose={() => onOpenChange(false)}
        />
      </DialogContent>
    </Dialog>
  )
}

interface BusinessObjectiveFormProps {
  threatModelId: string
  objective: BusinessObjective | null
  onClose: () => void
}

function BusinessObjectiveForm({ threatModelId, objective, onClose }: BusinessObjectiveFormProps) {
  const createMutation = useCreateBusinessObjective(threatModelId)
  const updateMutation = useUpdateBusinessObjective(threatModelId)
  const isSaving = createMutation.isPending || updateMutation.isPending

  const [name, setName] = useState(objective?.name ?? '')
  const [description, setDescription] = useState(objective?.description ?? '')
  const [criticality, setCriticality] = useState<string>(objective?.criticality || CRITICALITY_NONE)
  const [ownerName, setOwnerName] = useState(objective?.ownerName ?? '')

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault()
    const trimmedName = name.trim()
    if (!trimmedName) return
    const data = {
      name: trimmedName,
      description: description.trim(),
      criticality: criticality === CRITICALITY_NONE ? ('' as const) : (criticality as BusinessObjectiveCriticality),
      ownerName: ownerName.trim(),
    }
    const options = {
      onSuccess: () => onClose(),
      onError: (error: Error) => toast.error(error.message || 'Could not save the objective'),
    }
    if (objective) {
      updateMutation.mutate({ objectiveId: objective.id, data }, options)
    } else {
      createMutation.mutate(data, options)
    }
  }

  return (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="objective-name">Objective</Label>
            <Input
              id="objective-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Keep line 3 running 24/7"
              autoFocus
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="objective-criticality">Criticality</Label>
              <Select value={criticality} onValueChange={setCriticality}>
                <SelectTrigger id="objective-criticality">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={CRITICALITY_NONE}>Not set</SelectItem>
                  {BUSINESS_OBJECTIVE_CRITICALITIES.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="objective-owner">Owner</Label>
              <Input
                id="objective-owner"
                value={ownerName}
                onChange={(event) => setOwnerName(event.target.value)}
                placeholder="e.g. Plant manager"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="objective-description">Description</Label>
            <Textarea
              id="objective-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={isSaving}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || isSaving}>
              {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {objective ? 'Save' : 'Add objective'}
            </Button>
          </DialogFooter>
        </form>
  )
}
