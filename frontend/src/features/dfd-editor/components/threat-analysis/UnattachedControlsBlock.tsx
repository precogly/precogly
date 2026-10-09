/**
 * "Controls not linked to any threat" (plan J6, I3): kept controls with no
 * threat link, each with "Link to threat" and "Delete". The delete
 * confirmation says what goes with the control.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Link2, Loader2, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
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
  useCountermeasures,
  useDeleteCountermeasure,
  useLinkCountermeasure,
  type InstanceCountermeasure,
} from '@/features/threat-models/api/threats'
import { useCountermeasureComments } from '@/features/threat-models/api/risks'
import { COUNTERMEASURE_STATUS_CONFIG, type AnalysisThreat } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'
import { formatTargetList } from './countermeasure-utils'

interface UnattachedControlsBlockProps {
  threatModelId: string
  /** The model's scenarios, to pick a threat to link to. */
  threats: AnalysisThreat[]
}

export function UnattachedControlsBlock({ threatModelId, threats }: UnattachedControlsBlockProps) {
  const { data: countermeasures = [], isLoading } = useCountermeasures({ threatModel: threatModelId })
  const linkCountermeasure = useLinkCountermeasure()
  const deleteCountermeasure = useDeleteCountermeasure()
  const [linking, setLinking] = useState<InstanceCountermeasure | null>(null)
  const [linkThreatId, setLinkThreatId] = useState<string>('')
  const [deleting, setDeleting] = useState<InstanceCountermeasure | null>(null)
  const { data: deletingComments } = useCountermeasureComments(deleting?.id ?? null)

  const unattached = useMemo(
    () => countermeasures.filter((countermeasure) => countermeasure.threatLinks.length === 0),
    [countermeasures]
  )
  const sortedThreats = useMemo(() => [...threats].sort((left, right) => left.number - right.number), [threats])

  if (isLoading || unattached.length === 0) return null

  const deleteLosses = (countermeasure: InstanceCountermeasure): string[] => {
    const losses: string[] = []
    if (countermeasure.evidenceUrl) losses.push('its evidence link')
    if (deletingComments && deletingComments.length > 0) {
      losses.push(deletingComments.length === 1 ? '1 comment' : `${deletingComments.length} comments`)
    }
    if (countermeasure.targets.length > 0) losses.push(`its scope (${formatTargetList(countermeasure.targets)})`)
    if (countermeasure.assignedOwnerEmail) losses.push(`its owner (${countermeasure.assignedOwnerEmail})`)
    return losses
  }

  return (
    <div className="rounded-lg border border-dashed p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium">Controls not linked to any threat</div>
        <Badge variant="outline" className="text-xs">
          {unattached.length}
        </Badge>
      </div>
      <p className="mb-2 text-xs text-muted-foreground">
        Kept controls with no threat link. They are left out of gap counts until linked.
      </p>
      <ul className="divide-y">
        {unattached.map((countermeasure) => {
          const statusConfig = COUNTERMEASURE_STATUS_CONFIG[countermeasure.status]
          const name = countermeasure.countermeasureNameDisplay || `Countermeasure ${countermeasure.number}`
          return (
            <li key={countermeasure.id} className="flex items-center justify-between gap-2 py-1.5">
              <div className="flex min-w-0 items-center gap-2">
                <NumberBadge number={countermeasure.displayNumber} />
                <span className="truncate text-sm">{name}</span>
                <span
                  className="shrink-0 rounded px-1.5 py-0.5 text-[10px]"
                  style={{ backgroundColor: `${statusConfig.color}20`, color: statusConfig.color }}
                >
                  {statusConfig.label}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 text-xs"
                  onClick={() => {
                    setLinking(countermeasure)
                    setLinkThreatId('')
                  }}
                >
                  <Link2 className="h-3 w-3" /> Link to threat
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 text-xs text-muted-foreground hover:text-destructive"
                  onClick={() => setDeleting(countermeasure)}
                >
                  <Trash2 className="h-3 w-3" /> Delete
                </Button>
              </div>
            </li>
          )
        })}
      </ul>

      <Dialog open={linking !== null} onOpenChange={(isOpen) => !isOpen && setLinking(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              Link {linking?.displayNumber} {linking?.countermeasureNameDisplay} to a threat
            </DialogTitle>
            <DialogDescription>The control counts for the threat it is linked to.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <Label>Threat</Label>
            <Select value={linkThreatId} onValueChange={setLinkThreatId}>
              <SelectTrigger aria-label="Threat to link">
                <SelectValue placeholder="Choose a threat" />
              </SelectTrigger>
              <SelectContent>
                {sortedThreats.map((threat) => (
                  <SelectItem key={threat.id} value={String(threat.backendThreatId)}>
                    {threat.displayNumber} {threat.threatName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLinking(null)} disabled={linkCountermeasure.isPending}>
              Cancel
            </Button>
            <Button
              disabled={!linkThreatId || linkCountermeasure.isPending}
              onClick={() => {
                if (!linking) return
                linkCountermeasure.mutate(
                  { countermeasureId: linking.id, threatId: Number(linkThreatId) },
                  {
                    onSuccess: () => {
                      toast.success('Countermeasure linked')
                      setLinking(null)
                    },
                    onError: () => toast.error('Could not link the countermeasure'),
                  }
                )
              }}
            >
              {linkCountermeasure.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Link
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleting !== null} onOpenChange={(isOpen) => !isOpen && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {deleting?.displayNumber} {deleting?.countermeasureNameDisplay}?
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2">
                <p>
                  The control goes with its evidence, tests, comments and compliance mappings. This cannot be
                  undone.
                </p>
                {deleting && deleteLosses(deleting).length > 0 && (
                  <p>You would lose {deleteLosses(deleting).join(', ')}.</p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteCountermeasure.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteCountermeasure.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (!deleting) return
                deleteCountermeasure.mutate(deleting.id, {
                  onSuccess: () => {
                    toast.success('Countermeasure deleted')
                    setDeleting(null)
                  },
                  onError: () => toast.error('Could not delete the countermeasure'),
                })
              }}
            >
              {deleteCountermeasure.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
