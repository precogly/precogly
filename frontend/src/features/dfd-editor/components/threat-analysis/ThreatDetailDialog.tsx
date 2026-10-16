/**
 * The threat modal (UX simplification 3.2): everything about one threat that
 * used to sit inline in the threat row. The name is edited in place; then
 * State (triage, with the rationale prompt), the detail form (description,
 * severity, categories, actor, rationale, sources, impact, objectives), the
 * targets, and Delete. Saves work as they did inline: the name and triage at
 * once, categories as picked, the rest with Save.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Crosshair, Pencil, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useUpdateThreat, type ThreatPersona } from '@/features/threat-models/api/threats'
import { TRIAGE_STATUSES, type TriageStatus } from '@/types/triage'
import type { AnalysisThreat } from '../../types/threat-analysis'
import { deriveThreatStatus } from '../../types/threat-analysis'
import { NumberBadge } from './NumberBadge'
import { ThreatDetailPanel } from './ThreatDetailPanel'
import { ThreatStatusBadge } from './ThreatStatusBadge'
import { TARGET_TYPE_LABELS, isSameSelection, targetSelection, type AnalysisSelection } from './analysis-selection'

/** Triage states that ask for a rationale before they are saved. */
const STATES_NEEDING_RATIONALE: TriageStatus[] = ['accept', 'delegate', 'eliminate']

interface ThreatDetailDialogProps {
  threatModelId: string
  /** The threat shown; null closes the modal. */
  threat: AnalysisThreat | null
  onClose: () => void
  personas: ThreatPersona[]
  /** The tree selection, so the targets list marks the one already shown. */
  selection?: AnalysisSelection | null
  /** Makes the other targets links (the modal closes and the tree selects that target). */
  onSelectTarget?: (selection: AnalysisSelection) => void
  onOpenAbuseCase?: (abuseCaseId: number) => void
  onUpdateTriageStatus: (threatUiId: string, triageStatus: TriageStatus, decisionRationale?: string) => void
  onEditTargets: (threat: AnalysisThreat) => void
  onRequestDelete: (threat: AnalysisThreat) => void
}

export function ThreatDetailDialog({ threat, onClose, ...rest }: ThreatDetailDialogProps) {
  return (
    <Dialog
      open={threat !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className="sm:max-w-[720px]" data-testid="threat-detail-dialog">
        {/* Keyed by threat, so the forms start from this threat's values. */}
        {threat && <ThreatDetailContent key={threat.id} threat={threat} onClose={onClose} {...rest} />}
      </DialogContent>
    </Dialog>
  )
}

function ThreatDetailContent({
  threatModelId,
  threat,
  onClose,
  personas,
  selection = null,
  onSelectTarget,
  onOpenAbuseCase,
  onUpdateTriageStatus,
  onEditTargets,
  onRequestDelete,
}: Omit<ThreatDetailDialogProps, 'threat'> & { threat: AnalysisThreat }) {
  const updateThreatMutation = useUpdateThreat()
  const [isEditingName, setIsEditingName] = useState(false)
  const [nameValue, setNameValue] = useState(threat.threatName ?? '')
  const [pendingTriageStatus, setPendingTriageStatus] = useState<TriageStatus | null>(null)
  const [triageRationale, setTriageRationale] = useState('')

  const status = deriveThreatStatus(threat.countermeasures)
  const isShared = threat.targets.length > 1

  const saveName = () => {
    const trimmedName = nameValue.trim()
    setIsEditingName(false)
    if (!trimmedName || trimmedName === threat.threatName) {
      setNameValue(threat.threatName ?? '')
      return
    }
    updateThreatMutation.mutate(
      { threatId: threat.backendThreatId, data: { threatName: trimmedName } },
      {
        onSuccess: () => toast.success('Threat renamed'),
        onError: () => toast.error('Could not rename the threat'),
      }
    )
  }

  const handleTriageChange = (nextStatus: TriageStatus) => {
    if (STATES_NEEDING_RATIONALE.includes(nextStatus)) {
      setPendingTriageStatus(nextStatus)
      setTriageRationale('')
    } else {
      setPendingTriageStatus(null)
      onUpdateTriageStatus(threat.id, nextStatus)
    }
  }

  const confirmTriage = () => {
    if (!pendingTriageStatus || !triageRationale.trim()) return
    onUpdateTriageStatus(threat.id, pendingTriageStatus, triageRationale.trim())
    setPendingTriageStatus(null)
    setTriageRationale('')
  }

  const targetsSection = (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <div className="text-xs font-medium text-muted-foreground">Targets</div>
        <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" onClick={() => onEditTargets(threat)}>
          <Crosshair className="h-3 w-3" />
          Edit targets
        </Button>
      </div>
      {threat.wholeSystem ? (
        <p className="text-xs">The whole system (no targets).</p>
      ) : (
        <ul className="space-y-0.5 text-xs" data-testid="threat-targets">
          {threat.targets.map((target) => {
            const label = `${target.name || 'Unnamed'} (${TARGET_TYPE_LABELS[target.type]})`
            const targetAsSelection = targetSelection(target.type, target.id)
            const isShownTarget = isSameSelection(targetAsSelection, selection)
            return (
              <li key={`${target.type}-${target.id}`}>
                {onSelectTarget && !isShownTarget ? (
                  <button
                    type="button"
                    className="text-blue-600 hover:underline"
                    onClick={() => {
                      onClose()
                      onSelectTarget(targetAsSelection)
                    }}
                  >
                    {label}
                  </button>
                ) : (
                  <span>
                    {label}
                    {isShownTarget && <span className="text-muted-foreground"> (selected in the tree)</span>}
                  </span>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )

  return (
    <>
      <DialogHeader className="pr-8">
        <DialogTitle className="flex items-center gap-2 text-base">
          <NumberBadge number={threat.displayNumber} className="text-xs" />
          {isEditingName ? (
            <Input
              value={nameValue}
              onChange={(event) => setNameValue(event.target.value)}
              onBlur={saveName}
              onKeyDown={(event) => {
                if (event.key === 'Enter') saveName()
                if (event.key === 'Escape') {
                  // Cancel the rename without closing the modal.
                  event.stopPropagation()
                  event.preventDefault()
                  setNameValue(threat.threatName ?? '')
                  setIsEditingName(false)
                }
              }}
              className="h-8 text-sm"
              aria-label="Threat name"
              autoFocus
            />
          ) : (
            <button
              type="button"
              onClick={() => setIsEditingName(true)}
              className="group flex min-w-0 cursor-pointer items-center gap-1 text-left hover:text-primary"
              title="Click to rename"
            >
              <span className="truncate">{threat.threatName || 'Unnamed threat'}</span>
              <Pencil className="h-3 w-3 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100" />
            </button>
          )}
        </DialogTitle>
        <DialogDescription asChild>
          <div className="flex flex-wrap items-center gap-1.5">
            <ThreatStatusBadge status={status} />
            {isShared && (
              <Badge variant="outline" className="px-1 py-0 text-[10px] font-normal">
                shared
              </Badge>
            )}
            {threat.wholeSystem && (
              <Badge variant="outline" className="px-1 py-0 text-[10px] font-normal">
                whole system
              </Badge>
            )}
          </div>
        </DialogDescription>
      </DialogHeader>

      {threat.libraryMismatch && (
        <div className="flex items-center gap-1 text-xs text-amber-700">
          <AlertTriangle className="h-3 w-3 shrink-0" />
          The library no longer lists this threat here. It was kept because it has been edited.
        </div>
      )}

      <div className="space-y-2">
        <div className="text-xs font-medium text-muted-foreground">State</div>
        <Select value={threat.triageStatus} onValueChange={(value) => handleTriageChange(value as TriageStatus)}>
          <SelectTrigger className="h-8 w-[180px] text-xs" aria-label="Triage">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TRIAGE_STATUSES.map((entry) => (
              <SelectItem key={entry.value} value={entry.value} className="text-xs">
                {entry.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {pendingTriageStatus && (
          <div className="space-y-2 rounded-md border border-amber-200 bg-amber-50 p-2">
            <div className="text-xs font-medium text-amber-800">
              Rationale for {TRIAGE_STATUSES.find((entry) => entry.value === pendingTriageStatus)?.label}:
            </div>
            <input
              type="text"
              value={triageRationale}
              onChange={(event) => setTriageRationale(event.target.value)}
              placeholder="Why is this the right decision?"
              className="h-8 w-full rounded border bg-background px-2 text-sm"
              autoFocus
              onKeyDown={(event) => {
                if (event.key === 'Enter') confirmTriage()
              }}
            />
            <div className="flex items-center gap-2">
              <Button size="sm" className="h-7 text-xs" disabled={!triageRationale.trim()} onClick={confirmTriage}>
                Confirm
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 text-xs"
                onClick={() => {
                  setPendingTriageStatus(null)
                  setTriageRationale('')
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
      </div>

      <ThreatDetailPanel
        threatModelId={threatModelId}
        threat={threat}
        personas={personas}
        onOpenAbuseCase={
          onOpenAbuseCase
            ? (abuseCaseId) => {
                onClose()
                onOpenAbuseCase(abuseCaseId)
              }
            : undefined
        }
        trailingSection={targetsSection}
      />

      <DialogFooter className="sm:justify-between">
        <Button
          variant="ghost"
          size="sm"
          className="gap-1 text-destructive hover:bg-red-50 hover:text-destructive"
          onClick={() => onRequestDelete(threat)}
        >
          <Trash2 className="h-3.5 w-3.5" />
          Delete threat
        </Button>
        <Button variant="outline" size="sm" onClick={onClose}>
          Close
        </Button>
      </DialogFooter>
    </>
  )
}
