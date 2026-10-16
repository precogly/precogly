/**
 * Create or edit an inventory system (plan J1): name, owner, criticality,
 * lifecycle state, description. Used by the primary system select on the
 * model page and by the Systems settings page.
 */

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useCreateSystem, useUpdateSystem } from '@/features/threat-models/api/threat-models'
import type { System, SystemLifecycleState } from '@/features/threat-models/types/core'
import type { Criticality } from '@/types/domain'
import { SYSTEM_CRITICALITIES, SYSTEM_LIFECYCLE_STATES } from './system-options'

interface SystemFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Edit this system; omit to create one. */
  system?: System | null
  onSaved?: (system: System) => void
}

export function SystemFormDialog({ open, onOpenChange, system, onSaved }: SystemFormDialogProps) {
  const isEditing = !!system
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <DialogTitle>{isEditing ? 'Edit system' : 'Create new system'}</DialogTitle>
          <DialogDescription>
            {isEditing ? 'Change the inventory system.' : 'An inventory system a threat model can be about.'}
          </DialogDescription>
        </DialogHeader>
        {/* The content unmounts when the dialog closes, so the form starts fresh on every open. */}
        <SystemForm key={system?.id ?? 'new'} system={system ?? null} onSaved={onSaved} onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}

interface SystemFormProps {
  system: System | null
  onSaved?: (system: System) => void
  onClose: () => void
}

function SystemForm({ system, onSaved, onClose }: SystemFormProps) {
  const [name, setName] = useState(system?.name ?? '')
  const [owner, setOwner] = useState(system?.owner ?? '')
  const [criticality, setCriticality] = useState<Criticality>(system?.criticality ?? 'medium')
  const [lifecycleState, setLifecycleState] = useState<SystemLifecycleState>(system?.lifecycleState ?? 'production')
  const [description, setDescription] = useState(system?.description ?? '')

  const createSystemMutation = useCreateSystem()
  const updateSystemMutation = useUpdateSystem()
  const isSaving = createSystemMutation.isPending || updateSystemMutation.isPending

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    const trimmedName = name.trim()
    if (!trimmedName) return
    const payload = {
      name: trimmedName,
      owner: owner.trim(),
      criticality,
      lifecycleState,
      description: description.trim(),
    }
    try {
      const saved = system
        ? await updateSystemMutation.mutateAsync({ systemId: system.id, data: payload })
        : await createSystemMutation.mutateAsync(payload)
      onSaved?.(saved)
      onClose()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Could not save the system')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="system-form-name">Name</Label>
        <Input
          id="system-form-name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="e.g. Bottling Line 3"
          autoFocus
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="system-form-owner">Owner</Label>
        <Input
          id="system-form-owner"
          value={owner}
          onChange={(event) => setOwner(event.target.value)}
          placeholder="e.g. Plant manager"
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="system-form-criticality">Criticality</Label>
          <Select value={criticality} onValueChange={(value) => setCriticality(value as Criticality)}>
            <SelectTrigger id="system-form-criticality">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SYSTEM_CRITICALITIES.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="system-form-lifecycle">Lifecycle state</Label>
          <Select value={lifecycleState} onValueChange={(value) => setLifecycleState(value as SystemLifecycleState)}>
            <SelectTrigger id="system-form-lifecycle">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SYSTEM_LIFECYCLE_STATES.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="system-form-description">Description</Label>
        <Textarea
          id="system-form-description"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          rows={3}
          placeholder="What the system is and does"
        />
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={isSaving}>
          Cancel
        </Button>
        <Button type="submit" disabled={!name.trim() || isSaving}>
          {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {system ? 'Save' : 'Create system'}
        </Button>
      </DialogFooter>
    </form>
  )
}
