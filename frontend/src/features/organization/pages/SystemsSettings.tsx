/**
 * Settings / Systems (plan J1): the organization's inventory systems with
 * list, create, edit and delete. The list says how many models use a system
 * as their primary system and how many system assets link to it. A system
 * that is some model's primary system cannot be deleted; the 409 body names
 * the models. Deleting otherwise only unlinks its system assets (H5).
 */

import { useState } from 'react'
import { AlertCircle, Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
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
import { ApiError } from '@/lib/api'
import { useDeleteSystem, useSystems } from '@/features/threat-models/api/threat-models'
import { SystemFormDialog } from '@/features/threat-models/components/SystemFormDialog'
import { SYSTEM_CRITICALITIES, SYSTEM_LIFECYCLE_STATES } from '@/features/threat-models/components/system-options'
import type { System, SystemDeleteConflict } from '@/features/threat-models/types/core'

function criticalityLabel(value: System['criticality']): string {
  if (!value) return ''
  return SYSTEM_CRITICALITIES.find((option) => option.value === value)?.label ?? value
}

function lifecycleLabel(value: System['lifecycleState']): string {
  if (!value) return ''
  return SYSTEM_LIFECYCLE_STATES.find((option) => option.value === value)?.label ?? value
}

function countLabel(count: number | undefined, singular: string): string {
  const total = count ?? 0
  return `${total} ${total === 1 ? singular : `${singular}s`}`
}

export function SystemsSettings() {
  const { data: systems = [], isLoading } = useSystems()
  const deleteMutation = useDeleteSystem()

  const [formOpen, setFormOpen] = useState(false)
  const [editingSystem, setEditingSystem] = useState<System | null>(null)
  const [systemToDelete, setSystemToDelete] = useState<System | null>(null)
  const [deleteConflict, setDeleteConflict] = useState<SystemDeleteConflict | null>(null)

  const openCreate = () => {
    setEditingSystem(null)
    setFormOpen(true)
  }

  const openEdit = (system: System) => {
    setEditingSystem(system)
    setFormOpen(true)
  }

  const closeDelete = () => {
    setSystemToDelete(null)
    setDeleteConflict(null)
  }

  const handleDelete = () => {
    if (!systemToDelete) return
    deleteMutation.mutate(systemToDelete.id, {
      onSuccess: () => {
        toast.success(`System "${systemToDelete.name}" deleted`)
        closeDelete()
      },
      onError: (error) => {
        if (error instanceof ApiError && error.status === 409) {
          setDeleteConflict(error.data as SystemDeleteConflict)
          return
        }
        toast.error(error instanceof Error ? error.message : 'Could not delete the system')
      },
    })
  }

  const sortedSystems = [...systems].sort((first, second) => first.name.localeCompare(second.name))

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Systems</CardTitle>
              <CardDescription>
                The systems your threat models are about. One model has one primary system; other systems it
                touches are drawn on its diagrams as system boxes.
              </CardDescription>
            </div>
            <Button onClick={openCreate} className="gap-2">
              <Plus className="h-4 w-4" />
              New system
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : sortedSystems.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">
              No systems yet. A model with no primary system still works; create one here or from the model page.
            </p>
          ) : (
            <Table data-testid="systems-table">
              <TableHeader>
                <TableRow>
                  <TableHead>System</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Criticality</TableHead>
                  <TableHead>Lifecycle</TableHead>
                  <TableHead>Primary system of</TableHead>
                  <TableHead>Linked from</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedSystems.map((system) => {
                  const isPrimarySomewhere = (system.primaryModelCount ?? 0) > 0
                  return (
                    <TableRow key={system.id} data-testid="system-row">
                      <TableCell>
                        <div className="font-medium">{system.name}</div>
                        {system.description && (
                          <div className="text-xs text-muted-foreground line-clamp-1">{system.description}</div>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">{system.owner}</TableCell>
                      <TableCell className="text-sm">{criticalityLabel(system.criticality)}</TableCell>
                      <TableCell className="text-sm">{lifecycleLabel(system.lifecycleState)}</TableCell>
                      <TableCell className="text-sm">
                        {isPrimarySomewhere ? (
                          <Badge variant="secondary" className="text-xs">
                            {countLabel(system.primaryModelCount, 'model')}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">{countLabel(system.linkedComponentCount, 'system asset')}</TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            onClick={() => openEdit(system)}
                            aria-label={`Edit ${system.name}`}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-muted-foreground hover:text-destructive"
                            onClick={() => setSystemToDelete(system)}
                            aria-label={`Delete ${system.name}`}
                            title={
                              isPrimarySomewhere
                                ? 'This system is the primary system of a model. Give that model another primary system first.'
                                : undefined
                            }
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <SystemFormDialog open={formOpen} onOpenChange={setFormOpen} system={editingSystem} />

      <AlertDialog open={!!systemToDelete} onOpenChange={(open) => !open && closeDelete()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{systemToDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2 text-sm text-muted-foreground">
                {deleteConflict ? (
                  <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-red-800">
                    <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    <div>
                      <p>
                        "{systemToDelete?.name}" cannot be deleted while it is the primary system of{' '}
                        {deleteConflict.models.map((model) => model.name).join(', ')}. Give{' '}
                        {deleteConflict.models.length === 1 ? 'that model' : 'those models'} another primary system
                        first.
                      </p>
                    </div>
                  </div>
                ) : (
                  <p>
                    Deleting a system only unlinks the system boxes that point at it
                    {systemToDelete?.linkedComponentCount
                      ? ` (${countLabel(systemToDelete.linkedComponentCount, 'system asset')})`
                      : ''}
                    . Nothing inside those models is deleted.
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>{deleteConflict ? 'Close' : 'Cancel'}</AlertDialogCancel>
            {!deleteConflict && (
              <AlertDialogAction
                onClick={(event) => {
                  event.preventDefault()
                  handleDelete()
                }}
                disabled={deleteMutation.isPending}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                {deleteMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  'Delete system'
                )}
              </AlertDialogAction>
            )}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
