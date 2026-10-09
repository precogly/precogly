/**
 * "Manage personas" (plan J10): list, create, edit and delete the model's
 * threat personas. Delete says how many threats use the persona; the
 * backend clears the key on those threats.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
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
import {
  useCreateThreatPersona,
  useDeleteThreatPersona,
  useThreatPersonas,
  useUpdateThreatPersona,
  type CreateThreatPersonaInput,
  type ThreatPersona,
  type UpdateThreatPersonaInput,
} from '@/features/threat-models/api/threats'
import { symbolicNameFromName } from './persona-utils'

const SKILL_LEVELS = ['none', 'minimal', 'operational', 'adept'] as const

interface PersonaForm {
  name: string
  description: string
  isPerson: boolean
  maliciousIntent: boolean
  skillLevel: string
  motivation: string
  resources: string
  objectives: string
}

const EMPTY_FORM: PersonaForm = {
  name: '',
  description: '',
  isPerson: true,
  maliciousIntent: true,
  skillLevel: 'operational',
  motivation: '',
  resources: '',
  objectives: '',
}

function formFromPersona(persona: ThreatPersona): PersonaForm {
  return {
    name: persona.name,
    description: persona.description,
    isPerson: persona.isPerson,
    maliciousIntent: persona.maliciousIntent,
    skillLevel: persona.skillLevel || 'operational',
    motivation: persona.motivation,
    resources: persona.resources,
    objectives: persona.objectives,
  }
}

function threatCountLabel(count: number | undefined): string {
  if (count === undefined) return ''
  return count === 1 ? '1 threat' : `${count} threats`
}

interface ManagePersonasDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
}

export function ManagePersonasDialog({ open, onOpenChange, threatModelId }: ManagePersonasDialogProps) {
  const { data: personas = [], isLoading } = useThreatPersonas(threatModelId)
  const createPersona = useCreateThreatPersona(threatModelId)
  const updatePersona = useUpdateThreatPersona(threatModelId)
  const deletePersona = useDeleteThreatPersona(threatModelId)

  const [editing, setEditing] = useState<{ personaId: number | null; form: PersonaForm } | null>(null)
  const [deleting, setDeleting] = useState<ThreatPersona | null>(null)

  const isSaving = createPersona.isPending || updatePersona.isPending

  const handleSave = () => {
    if (!editing || !editing.form.name.trim()) return
    const data: CreateThreatPersonaInput = {
      symbolicName: symbolicNameFromName(editing.form.name),
      name: editing.form.name.trim(),
      description: editing.form.description,
      isPerson: editing.form.isPerson,
      maliciousIntent: editing.form.maliciousIntent,
      skillLevel: editing.form.skillLevel,
      motivation: editing.form.motivation,
      resources: editing.form.resources,
      objectives: editing.form.objectives,
    }
    const onSuccess = () => {
      toast.success(editing.personaId === null ? 'Persona created' : 'Persona updated')
      setEditing(null)
    }
    const onError = () => toast.error('Could not save the persona')
    if (editing.personaId === null) {
      createPersona.mutate(data, { onSuccess, onError })
    } else {
      // The symbolic name is stable; a rename keeps it.
      const patch: UpdateThreatPersonaInput = { ...data }
      delete patch.symbolicName
      updatePersona.mutate({ personaId: editing.personaId, data: patch }, { onSuccess, onError })
    }
  }

  const updateForm = (patch: Partial<PersonaForm>) =>
    setEditing((current) => (current ? { ...current, form: { ...current.form, ...patch } } : current))

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Threat personas</DialogTitle>
            <DialogDescription>
              A persona is a named actor of this model. A threat has one actor: a persona, a built-in actor or text.
            </DialogDescription>
          </DialogHeader>

          {editing ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="persona-name">Name *</Label>
                <Input
                  id="persona-name"
                  value={editing.form.name}
                  onChange={(event) => updateForm({ name: event.target.value })}
                  placeholder="Disgruntled operator"
                  autoFocus
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="persona-description">Description</Label>
                <Textarea
                  id="persona-description"
                  rows={2}
                  value={editing.form.description}
                  onChange={(event) => updateForm({ description: event.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={editing.form.isPerson}
                    onCheckedChange={(checked) => updateForm({ isPerson: checked === true })}
                  />
                  A person (not a system)
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={editing.form.maliciousIntent}
                    onCheckedChange={(checked) => updateForm({ maliciousIntent: checked === true })}
                  />
                  Malicious intent
                </label>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label>Skill level</Label>
                  <Select value={editing.form.skillLevel} onValueChange={(value) => updateForm({ skillLevel: value })}>
                    <SelectTrigger aria-label="Skill level">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SKILL_LEVELS.map((level) => (
                        <SelectItem key={level} value={level} className="capitalize">
                          {level}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="persona-motivation">Motivation</Label>
                  <Input
                    id="persona-motivation"
                    value={editing.form.motivation}
                    onChange={(event) => updateForm({ motivation: event.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="persona-resources">Resources</Label>
                  <Input
                    id="persona-resources"
                    value={editing.form.resources}
                    onChange={(event) => updateForm({ resources: event.target.value })}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="persona-objectives">Objectives</Label>
                  <Input
                    id="persona-objectives"
                    value={editing.form.objectives}
                    onChange={(event) => updateForm({ objectives: event.target.value })}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setEditing(null)} disabled={isSaving}>
                  Cancel
                </Button>
                <Button onClick={handleSave} disabled={!editing.form.name.trim() || isSaving}>
                  {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  {editing.personaId === null ? 'Create persona' : 'Save persona'}
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              {isLoading ? (
                <p className="text-sm text-muted-foreground">Loading personas</p>
              ) : personas.length === 0 ? (
                <p className="text-sm text-muted-foreground">No personas yet.</p>
              ) : (
                <ul className="divide-y rounded-md border">
                  {personas.map((persona) => (
                    <li key={persona.id} className="flex items-center justify-between gap-2 px-3 py-2">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium">{persona.name}</div>
                        <div className="text-xs text-muted-foreground">
                          Used by {threatCountLabel(persona.threatCount ?? 0)}
                          {persona.description ? ` · ${persona.description}` : ''}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          aria-label={`Edit ${persona.name}`}
                          onClick={() => setEditing({ personaId: persona.id, form: formFromPersona(persona) })}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-muted-foreground hover:text-destructive"
                          aria-label={`Delete ${persona.name}`}
                          onClick={() => setDeleting(persona)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={() => onOpenChange(false)}>
                  Close
                </Button>
                <Button onClick={() => setEditing({ personaId: null, form: EMPTY_FORM })}>
                  <Plus className="mr-1 h-4 w-4" /> New persona
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleting !== null} onOpenChange={(isOpen) => !isOpen && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete persona "{deleting?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleting?.threatCount
                ? `${threatCountLabel(deleting.threatCount)} use this persona. They keep no actor.`
                : 'No threat uses this persona.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePersona.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deletePersona.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (!deleting) return
                deletePersona.mutate(deleting.id, {
                  onSuccess: () => {
                    toast.success('Persona deleted')
                    setDeleting(null)
                  },
                  onError: () => toast.error('Could not delete the persona'),
                })
              }}
            >
              {deletePersona.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
