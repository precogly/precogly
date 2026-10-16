/**
 * Use cases of a model: a table with the abuse case count and gap badges,
 * plus create, edit and delete. Always shown, also when empty.
 */

import { useState } from 'react'
import { BookOpen, Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
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
import { UseCaseDialog } from '@/features/threat-models/components/use-cases/UseCaseDialog'
import { USE_CASE_GAP_LABELS, getUseCaseGaps } from '@/features/threat-models/components/use-cases/use-case-utils'

interface UseCasesCardProps {
  threatModelId: string
}

export function UseCasesCard({ threatModelId }: UseCasesCardProps) {
  const { data: useCases = [], isLoading } = useUseCases(threatModelId)
  const deleteMutation = useDeleteUseCase(threatModelId)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingUseCase, setEditingUseCase] = useState<UseCase | undefined>(undefined)
  const [useCaseToDelete, setUseCaseToDelete] = useState<UseCase | null>(null)

  const openCreate = () => {
    setEditingUseCase(undefined)
    setDialogOpen(true)
  }

  const openEdit = (useCase: UseCase) => {
    setEditingUseCase(useCase)
    setDialogOpen(true)
  }

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
          <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={openCreate}>
            <Plus className="h-3 w-3" />
            Use case
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading use cases
          </div>
        ) : useCases.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Describe what the system is for. Then ask how each use case can be abused.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Use case</TableHead>
                <TableHead className="text-xs text-right">Abuse cases</TableHead>
                <TableHead className="text-xs">Gaps</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {useCases.map((useCase) => (
                <TableRow key={useCase.id} data-testid="use-case-row">
                  <TableCell className="text-sm">
                    <div className="font-medium">{useCase.name}</div>
                    {useCase.description && (
                      <div className="text-xs text-muted-foreground line-clamp-2">{useCase.description}</div>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-right tabular-nums">{useCase.abuseCaseCount}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {getUseCaseGaps(useCase).map((gap) => (
                        <Badge key={gap} variant="outline" className="text-xs">
                          {USE_CASE_GAP_LABELS[gap]}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => openEdit(useCase)}
                        aria-label={`Edit ${useCase.name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        onClick={() => setUseCaseToDelete(useCase)}
                        aria-label={`Delete ${useCase.name}`}
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

      <UseCaseDialog
        threatModelId={threatModelId}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        useCase={editingUseCase}
      />

      <AlertDialog open={!!useCaseToDelete} onOpenChange={(open) => !open && setUseCaseToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{useCaseToDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              The use case is removed from this model and from its exports. Its abuse cases are kept.
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
