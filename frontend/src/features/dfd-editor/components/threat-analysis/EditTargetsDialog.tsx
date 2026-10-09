/**
 * "Edit targets" for a threat and "Applies to" for a countermeasure (plan
 * 11.3, J3). For a threat, removing the last target asks "make it a
 * whole-system threat" or "delete the threat" (I8); a countermeasure with no
 * targets simply applies to the whole system (section 4.3).
 *
 * Mount it when it opens (the callers render it conditionally), so its form
 * starts from the initial values every time.
 */

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
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
import { Button } from '@/components/ui/button'
import type { TargetRef } from '@/features/threat-models/api/threats'
import { TargetPicker } from './TargetPicker'
import { sameTargets } from './countermeasure-utils'

interface EditTargetsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  /** "T7 Edit targets" or "C3 Applies to". */
  title: string
  description?: string
  initialTargets: TargetRef[]
  initialWholeSystem?: boolean
  /** `threat`: no targets must mean whole-system (asks). `countermeasure`: no targets means whole system. */
  mode: 'threat' | 'countermeasure'
  isSaving?: boolean
  onSave: (targets: TargetRef[], wholeSystem: boolean) => void
  /** The "delete the threat" answer to the I8 question. */
  onDelete?: () => void
}

export function EditTargetsDialog({
  open,
  onOpenChange,
  threatModelId,
  title,
  description,
  initialTargets,
  initialWholeSystem = false,
  mode,
  isSaving = false,
  onSave,
  onDelete,
}: EditTargetsDialogProps) {
  const [targets, setTargets] = useState<TargetRef[]>(initialTargets)
  const [wholeSystem, setWholeSystem] = useState(initialWholeSystem)
  const [askLastTarget, setAskLastTarget] = useState(false)

  const unchanged = wholeSystem === initialWholeSystem && sameTargets(targets, initialTargets)

  const handleSave = () => {
    if (mode === 'threat' && targets.length === 0 && !wholeSystem) {
      setAskLastTarget(true)
      return
    }
    onSave(targets, mode === 'threat' ? wholeSystem : false)
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>
              {description ??
                (mode === 'threat'
                  ? 'A threat can sit on several components, flows, zones and boundaries, or on the whole system.'
                  : 'Where the control applies. Empty means the whole system. Scope does not change any threat status.')}
            </DialogDescription>
          </DialogHeader>
          <TargetPicker
            threatModelId={threatModelId}
            value={targets}
            onChange={setTargets}
            allowWholeSystem={mode === 'threat'}
            wholeSystem={wholeSystem}
            onWholeSystemChange={setWholeSystem}
            idPrefix={`edit-targets-${mode}`}
            emptyHint={mode === 'countermeasure' ? 'No targets: the control applies to the whole system.' : undefined}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSaving}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={isSaving || unchanged}>
              {isSaving ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Saving
                </>
              ) : (
                'Save'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={askLastTarget} onOpenChange={setAskLastTarget}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title.split(' ')[0]} would have no targets</AlertDialogTitle>
            <AlertDialogDescription>
              What should happen to this threat? A threat never becomes whole-system by accident.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                setAskLastTarget(false)
                setWholeSystem(true)
                onSave([], true)
              }}
            >
              Make it a whole-system threat
            </AlertDialogAction>
            {onDelete && (
              <AlertDialogAction
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                onClick={(event) => {
                  event.preventDefault()
                  setAskLastTarget(false)
                  onDelete()
                }}
              >
                Delete the threat
              </AlertDialogAction>
            )}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
