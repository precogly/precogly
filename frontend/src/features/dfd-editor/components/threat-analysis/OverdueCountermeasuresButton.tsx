/**
 * Every overdue countermeasure of the model in one list, the view a POA&M
 * reviewer works from (PR #559). The button sits in the Threat Analysis
 * toolbar and shows only when something is overdue. Overdue is the backend's
 * `days_overdue`: past the due date and not implemented, verified or platform.
 *
 * Clicking a row opens that countermeasure where it sits: the page selects a
 * threat it mitigates and opens its modal (`?countermeasure=C5`). A control
 * linked to no threat has no such place and is listed without a link.
 */

import { useMemo, useState } from 'react'
import { AlarmClock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useCountermeasures } from '@/features/threat-models/api/threats'
import type { CountermeasureStatus } from '../../types/threat-analysis'
import { CountermeasureStatusDot } from './CountermeasureCard'
import { NumberBadge } from './NumberBadge'
import { overdueCountermeasures } from './countermeasure-utils'

/** The server's largest page (`ClientSizedPagination.max_page_size`). */
const MAX_PAGE_SIZE = 200

interface OverdueCountermeasuresButtonProps {
  threatModelId: string
  /** Open the countermeasure with this display number (`C5`) in the components view. */
  onOpenCountermeasure: (displayNumber: string) => void
}

export function OverdueCountermeasuresButton({ threatModelId, onOpenCountermeasure }: OverdueCountermeasuresButtonProps) {
  const [open, setOpen] = useState(false)
  // Ask the server for the overdue ones only: an unfiltered list stops at the first page of 20.
  const { data: countermeasures = [] } = useCountermeasures({
    threatModel: threatModelId,
    overdue: true,
    pageSize: MAX_PAGE_SIZE,
  })
  const overdue = useMemo(() => overdueCountermeasures(countermeasures), [countermeasures])

  if (overdue.length === 0) return null

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="h-7 gap-1 border-red-300 text-xs text-red-700 hover:bg-red-50 hover:text-red-800"
        onClick={() => setOpen(true)}
        data-testid="model-overdue-button"
      >
        <AlarmClock className="h-3 w-3" />
        {overdue.length} overdue
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-3xl" data-testid="model-overdue-dialog">
          <DialogHeader>
            <DialogTitle>Overdue countermeasures</DialogTitle>
            <DialogDescription>
              Past their due date and not yet implemented, verified or platform. A due date comes from the countermeasure
              itself or, on import, from the target date of a risk response that names it.
            </DialogDescription>
          </DialogHeader>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Countermeasure</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Due</TableHead>
                <TableHead className="text-right text-xs">Days overdue</TableHead>
                <TableHead className="text-xs">Owner</TableHead>
                <TableHead className="text-xs">Threats</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {overdue.map((countermeasure) => {
                const linked = countermeasure.threatLinks.length > 0
                const name = countermeasure.countermeasureNameDisplay || `Countermeasure ${countermeasure.number}`
                return (
                  <TableRow key={countermeasure.id} data-overdue-number={countermeasure.displayNumber}>
                    <TableCell className="text-sm">
                      <div className="flex items-center gap-1.5">
                        <NumberBadge number={countermeasure.displayNumber} />
                        {linked ? (
                          <button
                            type="button"
                            className="text-left text-blue-600 hover:underline"
                            onClick={() => {
                              setOpen(false)
                              onOpenCountermeasure(countermeasure.displayNumber)
                            }}
                          >
                            {name}
                          </button>
                        ) : (
                          <span title="Not linked to any threat">{name}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <CountermeasureStatusDot status={countermeasure.status as CountermeasureStatus} />
                    </TableCell>
                    <TableCell className="text-sm tabular-nums">{countermeasure.dueDate}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums text-red-700">{countermeasure.daysOverdue}</TableCell>
                    <TableCell className="text-sm">{countermeasure.assignedOwnerEmail ?? ''}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {linked ? (
                          countermeasure.threatLinks.map((link) => <NumberBadge key={link.threatId} number={link.displayNumber} />)
                        ) : (
                          <span className="text-xs text-muted-foreground">None</span>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </DialogContent>
      </Dialog>
    </>
  )
}
