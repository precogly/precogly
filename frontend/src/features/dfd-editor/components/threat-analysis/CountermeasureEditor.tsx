/**
 * The countermeasure modal with the two dialogs it opens: "Edit compliance
 * mappings" and "Remove countermeasure?". One place owns their state and the
 * mutations, so the diagram's side panel edits a countermeasure the same way
 * the threat analysis screen does. The caller keeps which countermeasure is
 * open and where "Mitigates" links lead.
 *
 * The threat analysis column keeps its own copy of this wiring because its
 * handlers go through `useWorkspaceThreatAnalysis` for optimistic list updates.
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
  parseCountermeasureId,
  useUnlinkCountermeasure,
  useUpdateCountermeasure,
  type UpdateCountermeasureInput,
} from '@/features/threat-models/api/threats'
import { writeErrorMessage } from '@/features/threat-models/lib/write-error-message'
import type { AnalysisCountermeasure, AnalysisThreat, ComplianceStandardMapping } from '../../types/threat-analysis'
import { CountermeasureDetailDialog } from './CountermeasureDetailDialog'
import { EditComplianceMappingsDialog } from './EditComplianceMappingsDialog'

export interface CountermeasureEditorProps {
  threatModelId: string
  /** The threat the countermeasure is shown for. */
  threat: AnalysisThreat
  /** The countermeasure shown; null closes the modal. */
  countermeasure: AnalysisCountermeasure | null
  onClose: () => void
  /** Switch to another threat this control mitigates, by its backend id. */
  onOpenThreat: (backendThreatId: number) => void
  isSecurityTeam?: boolean
}

export function CountermeasureEditor({
  threatModelId,
  threat,
  countermeasure,
  onClose,
  onOpenThreat,
  isSecurityTeam,
}: CountermeasureEditorProps) {
  const [editingComplianceFor, setEditingComplianceFor] = useState<{
    backendId: number
    name: string
    mappings: ComplianceStandardMapping[]
  } | null>(null)
  const [deleteConfirmFor, setDeleteConfirmFor] = useState<{
    name: string
    backendId: number
    isShared?: boolean
  } | null>(null)

  const updateCountermeasure = useUpdateCountermeasure()
  const unlinkCountermeasure = useUnlinkCountermeasure()

  const save = (countermeasureUiId: string, data: UpdateCountermeasureInput, failureMessage: string) => {
    const parsed = parseCountermeasureId(countermeasureUiId)
    if (parsed.type !== 'backend' || parsed.id === null) return
    updateCountermeasure.mutate(
      { countermeasureId: parsed.id, data },
      { onError: (error) => toast.error(writeErrorMessage(error, failureMessage)) }
    )
  }

  const handleConfirmDelete = () => {
    if (!deleteConfirmFor) return
    const { isShared, backendId } = deleteConfirmFor
    unlinkCountermeasure.mutate(
      { countermeasureId: backendId, threatId: threat.backendThreatId },
      {
        onSuccess: () => {
          toast.success(isShared ? 'Countermeasure unlinked' : 'Countermeasure removed')
          setDeleteConfirmFor(null)
          onClose()
        },
        onError: () => toast.error(isShared ? 'Could not unlink the countermeasure' : 'Could not remove the countermeasure'),
      }
    )
  }

  return (
    <>
      <CountermeasureDetailDialog
        threatModelId={threatModelId}
        threat={threat}
        countermeasure={countermeasure}
        onClose={onClose}
        isSecurityTeam={isSecurityTeam}
        onStatusChange={(countermeasureUiId, status, notes) =>
          save(
            countermeasureUiId,
            { status, ...(notes !== undefined && { waiverReason: notes }) },
            'Could not change the status'
          )
        }
        onAssignOwner={(countermeasureUiId, assignee, newStatus) =>
          save(
            countermeasureUiId,
            { assignedOwner: assignee.userId, ...(newStatus && { status: newStatus }) },
            'Could not assign the owner'
          )
        }
        onPriorityChange={(countermeasureUiId, priority) =>
          save(countermeasureUiId, { priority }, 'Could not change the priority')
        }
        onDueDateChange={(countermeasureUiId, dueDate) =>
          save(countermeasureUiId, { dueDate }, 'Could not change the due date')
        }
        onExternalTicketChange={(countermeasureUiId, externalTicketUrl) =>
          save(countermeasureUiId, { externalTicketUrl }, 'Could not save the ticket link')
        }
        onRequestDelete={(target) => {
          if (target.backendCountermeasureId === undefined) return
          setDeleteConfirmFor({
            name: target.countermeasureName || target.countermeasureId,
            backendId: target.backendCountermeasureId,
            isShared: target.isShared,
          })
        }}
        onEditCompliance={(target) => {
          if (target.backendCountermeasureId === undefined) return
          setEditingComplianceFor({
            backendId: target.backendCountermeasureId,
            name: target.countermeasureName || target.countermeasureId,
            mappings: target.standardMappings || [],
          })
        }}
        onOpenThreat={onOpenThreat}
      />

      {editingComplianceFor && (
        <EditComplianceMappingsDialog
          open
          onOpenChange={(open) => {
            if (!open) setEditingComplianceFor(null)
          }}
          countermeasureId={editingComplianceFor.backendId}
          countermeasureName={editingComplianceFor.name}
          knownMappings={editingComplianceFor.mappings}
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
            <AlertDialogTitle>
              {deleteConfirmFor?.isShared ? 'Remove countermeasure from this threat?' : 'Remove countermeasure?'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleteConfirmFor?.isShared
                ? `"${deleteConfirmFor.name}" stays linked to the other threats it mitigates.`
                : `"${deleteConfirmFor?.name}" loses its link to this threat. An untouched generated control is deleted; anything edited is kept and listed as not linked to any threat.`}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={unlinkCountermeasure.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleConfirmDelete()
              }}
              disabled={unlinkCountermeasure.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {unlinkCountermeasure.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Removing
                </>
              ) : (
                'Remove'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
