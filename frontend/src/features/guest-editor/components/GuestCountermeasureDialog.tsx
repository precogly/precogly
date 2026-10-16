import { useState } from 'react'
import { Plus, Check, Info } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GUEST_CONTROL_FUNCTIONS, GUEST_CONTROL_NATURES, countermeasureDisplayNumber, threatDisplayNumber } from '../types'
import type { GuestCountermeasure, GuestTargetRef, ControlFunction, ControlNature } from '../types'
import { GuestTargetPicker } from './GuestTargetPicker'

interface GuestCountermeasureDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The threat the dialog was opened from; preselected for a new countermeasure. */
  initialThreatId?: string | null
  editCountermeasure?: GuestCountermeasure
}

export function GuestCountermeasureDialog(props: GuestCountermeasureDialogProps) {
  const { open, onOpenChange } = props
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* The form mounts with the dialog, so its state starts fresh on every open. */}
      {open && <GuestCountermeasureDialogForm {...props} />}
    </Dialog>
  )
}

function GuestCountermeasureDialogForm({
  onOpenChange,
  initialThreatId,
  editCountermeasure,
}: GuestCountermeasureDialogProps) {
  const guestEditor = useGuestEditor()
  const [name, setName] = useState(editCountermeasure?.name ?? '')
  const [description, setDescription] = useState(editCountermeasure?.description ?? '')
  const [controlFunction, setControlFunction] = useState<ControlFunction[]>(
    editCountermeasure && editCountermeasure.controlFunction.length > 0 ? editCountermeasure.controlFunction : ['preventive']
  )
  const [controlNature, setControlNature] = useState<ControlNature>(editCountermeasure?.controlNature || 'technical')
  const [threatIds, setThreatIds] = useState<string[]>(editCountermeasure ? editCountermeasure.threatIds : initialThreatId ? [initialThreatId] : [])
  const [targets, setTargets] = useState<GuestTargetRef[]>(editCountermeasure?.targets ?? [])

  const isEditMode = !!editCountermeasure
  const allThreats = guestEditor?.getAllThreats() ?? []

  const handleToggleFunction = (value: ControlFunction) => {
    setControlFunction((prev) => {
      if (prev.includes(value)) {
        // Keep at least one function selected
        if (prev.length === 1) return prev
        return prev.filter((f) => f !== value)
      }
      return [...prev, value]
    })
  }

  const handleToggleThreat = (threatId: string) => {
    setThreatIds((prev) => (prev.includes(threatId) ? prev.filter((id) => id !== threatId) : [...prev, threatId]))
  }

  const canSubmit = name.trim().length > 0 && controlFunction.length > 0 && threatIds.length > 0

  const handleSubmit = () => {
    if (!canSubmit || !guestEditor) return

    if (isEditMode) {
      guestEditor.updateCountermeasure(editCountermeasure.id, {
        name: name.trim(),
        description: description.trim(),
        controlFunction,
        controlNature,
        threatIds,
        targets,
      })
    } else {
      guestEditor.addCountermeasure({
        name: name.trim(),
        description: description.trim(),
        controlFunction,
        controlNature,
        threatIds,
        targets,
      })
    }
    onOpenChange(false)
  }

  const hiddenScopeNote = editCountermeasure && editCountermeasure.hiddenTargetRefs.length > 0
    ? `Also applies to ${editCountermeasure.hiddenTargetRefs.length} element${editCountermeasure.hiddenTargetRefs.length === 1 ? '' : 's'} not on the diagram.`
    : null

  return (
    <DialogContent className="sm:max-w-[560px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditMode ? `Edit Countermeasure ${countermeasureDisplayNumber(editCountermeasure)}` : 'Add Countermeasure'}
          </DialogTitle>
          <DialogDescription>
            {isEditMode
              ? 'Change the countermeasure, the threats it mitigates and what it applies to.'
              : 'A countermeasure can mitigate several threats and apply to part of the system or all of it.'}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="countermeasure-name">Name *</Label>
            <Input
              id="countermeasure-name"
              placeholder="Enter countermeasure name..."
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && canSubmit) handleSubmit()
              }}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="countermeasure-description">Description</Label>
            <Textarea
              id="countermeasure-description"
              placeholder="Describe the countermeasure..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
            />
          </div>

          <div className="space-y-2">
            <Label>Mitigates *</Label>
            <p className="text-xs text-muted-foreground">The threats this countermeasure is linked to. Pick one or more.</p>
            <div className="rounded-md border p-2 max-h-40 overflow-y-auto space-y-1" data-testid="countermeasure-threats">
              {allThreats.length === 0 && (
                <p className="text-xs text-muted-foreground px-1 py-2">No threats yet.</p>
              )}
              {allThreats.map((threat) => (
                <div key={threat.id} className="flex items-center gap-2 px-1">
                  <Checkbox
                    id={`cm-threat-${threat.id}`}
                    checked={threatIds.includes(threat.id)}
                    onCheckedChange={() => handleToggleThreat(threat.id)}
                  />
                  <label htmlFor={`cm-threat-${threat.id}`} className="text-sm cursor-pointer truncate">
                    <span className="font-mono text-xs text-muted-foreground mr-1.5">{threatDisplayNumber(threat)}</span>
                    {threat.name}
                  </label>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Applies to</Label>
            <p className="text-xs text-muted-foreground">Leave empty when the countermeasure applies to the whole system.</p>
            <GuestTargetPicker
              nodes={guestEditor?.nodes ?? []}
              edges={guestEditor?.edges ?? []}
              selected={targets}
              onChange={setTargets}
              hiddenNote={hiddenScopeNote}
              idPrefix="countermeasure-target"
            />
          </div>

          <div className="space-y-2">
            <Label>Control Function *</Label>
            <p className="text-xs text-muted-foreground">What the control does. Select one or more.</p>
            <div className="space-y-1.5 rounded-md border p-3">
              {GUEST_CONTROL_FUNCTIONS.map((opt) => (
                <div key={opt.value} className="flex items-start gap-2">
                  <Checkbox
                    id={`fn-${opt.value}`}
                    checked={controlFunction.includes(opt.value)}
                    onCheckedChange={() => handleToggleFunction(opt.value)}
                    className="mt-0.5"
                  />
                  <label
                    htmlFor={`fn-${opt.value}`}
                    className="flex-1 text-sm leading-tight cursor-pointer select-none"
                  >
                    <span className="font-medium">{opt.label}</span>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Info className="inline-block h-3 w-3 ml-1 text-muted-foreground align-text-top" />
                      </TooltipTrigger>
                      <TooltipContent side="right" className="max-w-[260px]">
                        <p className="text-xs">{opt.description}</p>
                      </TooltipContent>
                    </Tooltip>
                  </label>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="countermeasure-control-nature">Control Nature *</Label>
            <p className="text-xs text-muted-foreground">How the control is implemented.</p>
            <Select
              value={controlNature}
              onValueChange={(v) => setControlNature(v as ControlNature)}
            >
              <SelectTrigger id="countermeasure-control-nature">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {GUEST_CONTROL_NATURES.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    <div className="flex items-center gap-1.5">
                      <span>{opt.label}</span>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Info className="h-3 w-3 text-muted-foreground shrink-0" />
                        </TooltipTrigger>
                        <TooltipContent side="right" className="max-w-[260px]">
                          <p className="text-xs">{opt.description}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            {isEditMode ? (
              <>
                <Check className="h-4 w-4 mr-2" />
                Save
              </>
            ) : (
              <>
                <Plus className="h-4 w-4 mr-2" />
                Add
              </>
            )}
          </Button>
        </DialogFooter>
    </DialogContent>
  )
}
