import { AlertTriangle, Loader2, Trash2 } from 'lucide-react'
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
import { useDeletePreview } from '@/features/threat-models/api/threat-models'
import type { ThreatModel } from '@/types'

interface DeleteThreatModelDialogProps {
  threatModel: ThreatModel | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => void
  isDeleting?: boolean
}

export function DeleteThreatModelDialog({
  threatModel,
  open,
  onOpenChange,
  onConfirm,
  isDeleting = false,
}: DeleteThreatModelDialogProps) {
  const { data: preview, isLoading: isLoadingPreview } = useDeletePreview(
    open && threatModel ? threatModel.id : null
  )

  if (!threatModel) return null

  const hasDFDs = (preview?.dfdsToDelete?.length ?? 0) > 0

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-lg">
        <AlertDialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
              <AlertTriangle className="h-5 w-5 text-red-600" />
            </div>
            <AlertDialogTitle>Delete Threat Model</AlertDialogTitle>
          </div>
          <AlertDialogDescription className="pt-2">
            Are you sure you want to delete <strong>"{threatModel.name}"</strong>? This action cannot be undone.
          </AlertDialogDescription>

          {isLoadingPreview ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              <span className="ml-2 text-sm text-muted-foreground">Loading preview...</span>
            </div>
          ) : preview ? (
            <div className="mt-3 space-y-3">
              {/* DFDs to be deleted */}
              {hasDFDs && (
                <div className="rounded-md bg-red-50 border border-red-200 p-3">
                  <div className="flex items-center gap-2 text-sm font-medium text-red-800 mb-2">
                    <Trash2 className="h-4 w-4" />
                    DFDs that will be deleted ({preview.dfdsToDelete.length})
                  </div>
                  <ul className="space-y-1">
                    {preview.dfdsToDelete.map((dfd) => (
                      <li key={dfd.id} className="text-sm text-red-700 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                        {dfd.name}
                        <span className="text-red-500 text-xs">({dfd.nodeCount} nodes)</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* No DFDs */}
              {!hasDFDs && (
                <div className="rounded-md bg-gray-50 border border-gray-200 p-3 text-sm text-gray-600">
                  This threat model has no associated DFDs.
                </div>
              )}

              {/* Other items that will be deleted */}
              <div className="rounded-md bg-amber-50 border border-amber-200 p-3 text-sm text-amber-800">
                <p className="font-medium mb-1">Also deleted:</p>
                <ul className="list-disc list-inside space-y-0.5 text-amber-700 text-xs">
                  {preview.componentsToDelete > 0 && (
                    <li>{preview.componentsToDelete} component{preview.componentsToDelete !== 1 ? 's' : ''}</li>
                  )}
                  {preview.flowsToDelete > 0 && (
                    <li>{preview.flowsToDelete} data flow{preview.flowsToDelete !== 1 ? 's' : ''}</li>
                  )}
                  {preview.threatsToDelete > 0 && (
                    <li>{preview.threatsToDelete} threat{preview.threatsToDelete !== 1 ? 's' : ''}</li>
                  )}
                  {preview.countermeasuresToDelete > 0 && (
                    <li>{preview.countermeasuresToDelete} countermeasure{preview.countermeasuresToDelete !== 1 ? 's' : ''}</li>
                  )}
                  <li>Blueprints, zones, boundaries, data assets and assumptions</li>
                  <li>Business objectives, use cases and the review state</li>
                  <li>Relationships to other models</li>
                </ul>
              </div>
            </div>
          ) : null}
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault()
              onConfirm()
            }}
            disabled={isDeleting || isLoadingPreview}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {isDeleting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Deleting...
              </>
            ) : (
              'Delete Threat Model'
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
