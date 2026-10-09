/**
 * Use cases are import and export only (plan J14): a read-only list with a
 * delete action, shown only when an import brought some in.
 */

import { useState } from 'react'
import { BookOpen, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
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
import { useDeleteUseCase, useUseCases } from '@/features/threat-models/api/threat-models'
import type { UseCase } from '@/features/threat-models/types/core'

interface UseCasesCardProps {
  threatModelId: string
}

export function UseCasesCard({ threatModelId }: UseCasesCardProps) {
  const { data: useCases = [] } = useUseCases(threatModelId)
  const deleteMutation = useDeleteUseCase(threatModelId)
  const [useCaseToDelete, setUseCaseToDelete] = useState<UseCase | null>(null)

  if (useCases.length === 0) return null

  const handleDelete = () => {
    if (!useCaseToDelete) return
    deleteMutation.mutate(useCaseToDelete.id, {
      onSuccess: () => {
        toast.success('Use case deleted')
        setUseCaseToDelete(null)
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not delete the use case'),
    })
  }

  return (
    <Card data-testid="use-cases-card">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-muted-foreground" />
            Use cases
          </CardTitle>
          <Badge variant="outline" className="text-xs">
            Read-only
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          Imported with the document. They cannot be edited here, only removed, and they export again as they came.
        </p>
      </CardHeader>
      <CardContent>
        <ul className="divide-y">
          {useCases.map((useCase) => (
            <li key={useCase.id} className="flex items-start justify-between gap-3 py-2" data-testid="use-case-row">
              <div className="min-w-0">
                <div className="text-sm font-medium">{useCase.name}</div>
                {useCase.description && (
                  <div className="text-xs text-muted-foreground line-clamp-2">{useCase.description}</div>
                )}
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 gap-1 px-2 text-xs text-muted-foreground hover:text-destructive"
                onClick={() => setUseCaseToDelete(useCase)}
              >
                <Trash2 className="h-3 w-3" />
                Delete
              </Button>
            </li>
          ))}
        </ul>
      </CardContent>

      <AlertDialog open={!!useCaseToDelete} onOpenChange={(open) => !open && setUseCaseToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{useCaseToDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              The use case is removed from this model and from its exports. This cannot be undone here.
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
