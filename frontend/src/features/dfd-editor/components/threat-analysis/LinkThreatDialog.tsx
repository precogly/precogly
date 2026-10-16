/**
 * "Link existing threat": pick one of the model's threats (search by T number
 * or name) and link it to an abuse case. The threats searched are all threats
 * of the model, whatever the diagram filter of the page is. The save links the
 * one threat on the server, so a stale copy of the abuse case cannot drop links.
 */

import { useState } from 'react'
import { Loader2, Search } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { useLinkAbuseCaseThreat } from '@/features/threat-models/api/threat-models'
import { errorMessages } from '@/features/threat-models/components/use-cases/use-case-utils'
import type { AbuseCase } from '@/features/threat-models/types/core'
import type { AnalysisThreat } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'
import { filterLinkableThreats } from './use-case-view-utils'

interface LinkThreatDialogProps {
  threatModelId: string
  abuseCase: AbuseCase | null
  /** All threats of the model, not filtered by diagram. */
  threats: AnalysisThreat[]
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function LinkThreatDialog({ threatModelId, abuseCase, threats, open, onOpenChange }: LinkThreatDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Link existing threat</DialogTitle>
          <DialogDescription>
            Pick a threat of this model that comes from {abuseCase ? `"${abuseCase.name}"` : 'this abuse case'}.
          </DialogDescription>
        </DialogHeader>
        {abuseCase && (
          <LinkThreatForm
            key={abuseCase.id}
            threatModelId={threatModelId}
            abuseCase={abuseCase}
            threats={threats}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function LinkThreatForm({
  threatModelId,
  abuseCase,
  threats,
  onClose,
}: {
  threatModelId: string
  abuseCase: AbuseCase
  threats: AnalysisThreat[]
  onClose: () => void
}) {
  const [query, setQuery] = useState('')
  const [pickedBackendId, setPickedBackendId] = useState<number | null>(null)
  const linkThreat = useLinkAbuseCaseThreat(threatModelId)

  const linkable = filterLinkableThreats(
    threats,
    abuseCase.threats.map((threat) => threat.id),
    query
  )

  const handleLink = () => {
    if (pickedBackendId === null) return
    linkThreat.mutate(
      { abuseCaseId: abuseCase.id, threatId: pickedBackendId },
      {
        onSuccess: () => {
          toast.success('Threat linked')
          onClose()
        },
        onError: (error) => toast.error(errorMessages(error, 'Could not link the threat')[0]),
      }
    )
  }

  return (
    <>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search by T number or name"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="pl-9"
          aria-label="Search threats"
        />
      </div>
      <ScrollArea className="h-[260px] rounded-md border">
        {linkable.length === 0 ? (
          <p className="p-4 text-center text-sm text-muted-foreground">
            {query ? 'No threat matches' : 'No unlinked threats in this model.'}
          </p>
        ) : (
          <div className="space-y-1 p-2">
            {linkable.map((threat) => (
              <button
                key={threat.backendThreatId}
                type="button"
                onClick={() => setPickedBackendId(threat.backendThreatId)}
                className={cn(
                  'flex w-full items-center gap-2 rounded-md p-2 text-left text-sm transition-colors',
                  pickedBackendId === threat.backendThreatId ? 'border border-primary bg-primary/10' : 'hover:bg-muted'
                )}
              >
                <NumberBadge number={threat.displayNumber} />
                <span className="truncate">{threat.threatName || 'Unnamed threat'}</span>
              </button>
            ))}
          </div>
        )}
      </ScrollArea>
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button onClick={handleLink} disabled={pickedBackendId === null || linkThreat.isPending}>
          {linkThreat.isPending ? (
            <>
              <Loader2 className="mr-1 h-3 w-3 animate-spin" /> Linking
            </>
          ) : (
            'Link threat'
          )}
        </Button>
      </DialogFooter>
    </>
  )
}
