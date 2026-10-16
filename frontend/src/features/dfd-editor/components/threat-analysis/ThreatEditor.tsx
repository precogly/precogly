/**
 * The threat modal with the two dialogs it opens: "Edit targets" and
 * "Delete threat?". One place owns their state and their mutations, so the
 * threat analysis list and the diagram's side panel edit a threat the same
 * way. The caller keeps which threat is open and how triage is saved.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
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
  useDeleteThreat,
  useSetThreatTargets,
  useThreatPersonas,
  type TargetRef,
} from '@/features/threat-models/api/threats'
import type { TriageStatus } from '@/types/triage'
import type { AnalysisThreat } from '../../types/threat-analysis'
import { EditTargetsDialog } from './EditTargetsDialog'
import { ThreatDetailDialog } from './ThreatDetailDialog'
import { type AnalysisSelection } from './analysis-selection'

export interface ThreatEditorProps {
  threatModelId: string
  /** The threat shown; null closes the modal. */
  threat: AnalysisThreat | null
  onClose: () => void
  onUpdateTriageStatus: (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  /** The tree selection, so the modal's targets list marks the one already shown. */
  selection?: AnalysisSelection | null
  /** Makes the modal's other targets clickable. */
  onSelectTarget?: (selection: AnalysisSelection) => void
  /** Makes a threat's "From abuse cases" names links. */
  onOpenAbuseCase?: (abuseCaseId: number) => void
  /** Called after the targets were saved. */
  onTargetsSaved?: (wholeSystem: boolean) => void
  /** Called after the threat was deleted; the caller forgets the open threat. */
  onDeleted?: () => void
}

export function ThreatEditor({
  threatModelId,
  threat,
  onClose,
  onUpdateTriageStatus,
  selection = null,
  onSelectTarget,
  onOpenAbuseCase,
  onTargetsSaved,
  onDeleted,
}: ThreatEditorProps) {
  const [deleteConfirmFor, setDeleteConfirmFor] = useState<{ backendId: number; name: string } | null>(null)
  const [editingTargetsFor, setEditingTargetsFor] = useState<AnalysisThreat | null>(null)

  const { data: personas = [] } = useThreatPersonas(threatModelId)
  const setThreatTargetsMutation = useSetThreatTargets()
  const deleteThreatMutation = useDeleteThreat()

  const requestDelete = (target: AnalysisThreat) =>
    setDeleteConfirmFor({ backendId: target.backendThreatId, name: target.threatName || 'this threat' })

  const handleConfirmDelete = () => {
    if (!deleteConfirmFor) return
    deleteThreatMutation.mutate(deleteConfirmFor.backendId, {
      onSuccess: () => {
        toast.success('Threat deleted')
        setDeleteConfirmFor(null)
        setEditingTargetsFor(null)
        onDeleted?.()
      },
      onError: () => toast.error('Could not delete the threat'),
    })
  }

  const handleSaveTargets = (targets: TargetRef[], wholeSystem: boolean) => {
    if (!editingTargetsFor) return
    setThreatTargetsMutation.mutate(
      { threatId: editingTargetsFor.backendThreatId, targets, wholeSystem },
      {
        onSuccess: () => {
          toast.success(wholeSystem ? 'Now a whole-system threat' : 'Targets saved')
          setEditingTargetsFor(null)
          onTargetsSaved?.(wholeSystem)
        },
        onError: () => toast.error('Could not save the targets'),
      }
    )
  }

  return (
    <>
      <ThreatDetailDialog
        threatModelId={threatModelId}
        threat={threat}
        onClose={onClose}
        personas={personas}
        selection={selection}
        onSelectTarget={onSelectTarget}
        onOpenAbuseCase={onOpenAbuseCase}
        onUpdateTriageStatus={onUpdateTriageStatus}
        onEditTargets={setEditingTargetsFor}
        onRequestDelete={requestDelete}
      />

      {editingTargetsFor && (
        <EditTargetsDialog
          open
          onOpenChange={(open) => {
            if (!open) setEditingTargetsFor(null)
          }}
          threatModelId={threatModelId}
          title={`${editingTargetsFor.displayNumber} Edit targets`}
          initialTargets={editingTargetsFor.targets.map((target) => ({ type: target.type, id: target.id }))}
          initialWholeSystem={editingTargetsFor.wholeSystem}
          mode="threat"
          isSaving={setThreatTargetsMutation.isPending}
          onSave={handleSaveTargets}
          onDelete={() => requestDelete(editingTargetsFor)}
        />
      )}

      <AlertDialog
        open={!!deleteConfirmFor}
        onOpenChange={(open) => {
          if (!open) setDeleteConfirmFor(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete threat?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes "{deleteConfirmFor?.name}" from every target it sits on. Untouched generated controls linked
              only to it go too. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteThreatMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDelete()
              }}
              disabled={deleteThreatMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteThreatMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Deleting
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
