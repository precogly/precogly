/**
 * The sign-off view before approving (plan 11.5): the assumptions that are
 * not verified and the risks still "Identified". It informs; it does not
 * block the approval.
 */

import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { ASSUMPTION_VALIDITY } from '@/types/domain'
import { useAssumptions } from '@/features/threat-models/api/threat-models'
import { useRisks } from '@/features/threat-models/api/risks'

interface ApproveSignOffDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  threatModelName: string
  onConfirm: () => void
  isApproving: boolean
}

function validityLabel(validity: string): string {
  return ASSUMPTION_VALIDITY.find((option) => option.value === validity)?.label ?? validity
}

export function ApproveSignOffDialog({
  open,
  onOpenChange,
  threatModelId,
  threatModelName,
  onConfirm,
  isApproving,
}: ApproveSignOffDialogProps) {
  const { data: assumptions = [], isLoading: isLoadingAssumptions } = useAssumptions(open ? threatModelId : null)
  const { data: openRisksPage, isLoading: isLoadingRisks } = useRisks(open ? threatModelId : null, {
    status: 'identified',
    pageSize: 200,
  })

  const unverifiedAssumptions = assumptions.filter((assumption) => assumption.validity !== 'verified')
  const openRisks = openRisksPage?.results ?? []
  const isLoading = isLoadingAssumptions || isLoadingRisks
  const nothingOpen = unverifiedAssumptions.length === 0 && openRisks.length === 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg" data-testid="approve-sign-off">
        <DialogHeader>
          <DialogTitle>Approve "{threatModelName}"?</DialogTitle>
          <DialogDescription>
            Approval records the model as it is now. Any later change to its content shows as
            "Changed since approval".
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Before you approve</h4>
          {isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Checking assumptions and risks
            </div>
          ) : nothingOpen ? (
            <p className="text-sm text-muted-foreground">
              Every assumption is verified and no risk is still "Identified".
            </p>
          ) : (
            <>
              {unverifiedAssumptions.length > 0 && (
                <section className="space-y-1.5">
                  <p className="text-sm font-medium">
                    {unverifiedAssumptions.length}{' '}
                    {unverifiedAssumptions.length === 1 ? 'assumption is' : 'assumptions are'} not verified
                  </p>
                  <ul className="max-h-40 overflow-y-auto space-y-1 text-sm">
                    {unverifiedAssumptions.map((assumption) => (
                      <li key={assumption.id} className="flex items-start gap-2">
                        <Badge variant="outline" className="text-xs shrink-0">
                          {validityLabel(assumption.validity)}
                        </Badge>
                        <span className="text-muted-foreground">{assumption.description}</span>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {openRisks.length > 0 && (
                <section className="space-y-1.5">
                  <p className="text-sm font-medium">
                    {openRisks.length} {openRisks.length === 1 ? 'risk is' : 'risks are'} still "Identified"
                  </p>
                  <ul className="max-h-40 overflow-y-auto space-y-1 text-sm text-muted-foreground">
                    {openRisks.map((risk) => (
                      <li key={risk.id}>{risk.name}</li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isApproving}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={isApproving || isLoading}>
            {isApproving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {nothingOpen ? 'Approve' : 'Approve anyway'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
