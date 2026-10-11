/**
 * The Review card on the model page (plan 11.5, 11.11 "Review" row).
 *
 * Core: reviewer and date, approver and date, the state badge, and the
 * Mark reviewed, Approve and Revoke buttons. Approving and revoking need
 * the Security Team role (D4). Advanced: lifecycle phase, valid from and
 * until, review frequency. An approval that came with an imported document
 * is history, not a live approval (D18).
 */

import { useState } from 'react'
import { ChevronDown, ChevronRight, ClipboardCheck, Loader2, ShieldCheck, Undo2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { ApiError } from '@/lib/api'
import { LIFECYCLE_PHASES, REVIEW_FREQUENCY_PRESETS, type LifecyclePhase } from '@/types/domain'
import {
  useApproveThreatModel,
  useMarkReviewed,
  useReviewState,
  useRevokeApproval,
  useUpdateThreatModel,
} from '@/features/threat-models/api/threat-models'
import type { ThreatModel } from '@/features/threat-models/types/core'
import { ApproveSignOffDialog } from './ApproveSignOffDialog'
import {
  REVIEW_DUE_BADGE_CLASS,
  REVIEW_FREQUENCY_CUSTOM,
  REVIEW_FREQUENCY_NONE,
  approvalStateBadgeClass,
  approvalStateLabel,
  dateInputToIso,
  dateInputValue,
  formatReviewDate,
  isIso8601Duration,
  reviewFrequencySelection,
  sourceDocumentApproval,
} from './review-utils'

const LIFECYCLE_NONE = 'none'

interface ReviewCardProps {
  threatModelId: string
  threatModelName: string
  isSecurityTeam: boolean
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'Only Security Team members can approve or revoke.'
    const detail = (error.data as { detail?: string; error?: string } | undefined)?.detail
    const body = (error.data as { error?: string } | undefined)?.error
    return detail ?? body ?? error.message ?? fallback
  }
  return error instanceof Error ? error.message : fallback
}

export function ReviewCard({ threatModelId, threatModelName, isSecurityTeam }: ReviewCardProps) {
  const { data: reviewState, isLoading } = useReviewState(threatModelId)
  const markReviewedMutation = useMarkReviewed(threatModelId)
  const approveMutation = useApproveThreatModel(threatModelId)
  const revokeMutation = useRevokeApproval(threatModelId)
  const updateThreatModelMutation = useUpdateThreatModel()

  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [signOffOpen, setSignOffOpen] = useState(false)
  // The select follows the stored value; "Custom" and its draft are local until saved.
  const [customChosen, setCustomChosen] = useState(false)
  const [customDraft, setCustomDraft] = useState<string | null>(null)
  const storedFrequency = reviewFrequencySelection(reviewState?.reviewFrequency)
  const frequencyPreset = customChosen ? REVIEW_FREQUENCY_CUSTOM : storedFrequency.preset
  const customFrequency = customDraft ?? storedFrequency.custom

  const approvalState = reviewState?.approvalState ?? 'none'
  const hasApproval = approvalState === 'approved' || approvalState === 'changed'
  const sourceApproval = sourceDocumentApproval(reviewState?.sourceDocumentReview)
  const securityTeamHint = isSecurityTeam ? undefined : 'Only Security Team members can approve'

  const saveField = (data: Partial<ThreatModel>, successMessage?: string) => {
    updateThreatModelMutation.mutate(
      { id: threatModelId, data },
      {
        onSuccess: () => {
          if (successMessage) toast.success(successMessage)
        },
        onError: (error) => toast.error(errorMessage(error, 'Could not save')),
      }
    )
  }

  const handleMarkReviewed = () => {
    markReviewedMutation.mutate(undefined, {
      onSuccess: () => toast.success('Marked as reviewed'),
      onError: (error) => toast.error(errorMessage(error, 'Could not mark as reviewed')),
    })
  }

  const handleApprove = () => {
    approveMutation.mutate(undefined, {
      onSuccess: () => {
        setSignOffOpen(false)
        toast.success('Threat model approved')
      },
      onError: (error) => toast.error(errorMessage(error, 'Could not approve')),
    })
  }

  const handleRevoke = () => {
    revokeMutation.mutate(undefined, {
      onSuccess: () => toast.success('Approval revoked'),
      onError: (error) => toast.error(errorMessage(error, 'Could not revoke the approval')),
    })
  }

  const handleFrequencyPresetChange = (value: string) => {
    if (value === REVIEW_FREQUENCY_CUSTOM) {
      setCustomChosen(true)
      return
    }
    setCustomChosen(false)
    setCustomDraft(null)
    saveField({ reviewFrequency: value === REVIEW_FREQUENCY_NONE ? '' : value })
  }

  const handleCustomFrequencySave = () => {
    const trimmed = customFrequency.trim()
    if (!isIso8601Duration(trimmed)) {
      toast.error('Enter an ISO 8601 duration such as P2W or P18M')
      return
    }
    setCustomChosen(false)
    setCustomDraft(null)
    saveField({ reviewFrequency: trimmed })
  }

  return (
    <Card data-testid="review-card">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium">Review</CardTitle>
          <div className="flex flex-wrap items-center justify-end gap-1">
            <Badge
              variant="outline"
              className={cn('text-xs', approvalStateBadgeClass(approvalState))}
              data-testid="approval-state"
            >
              {approvalStateLabel(approvalState)}
            </Badge>
            {reviewState?.reviewDue && (
              <Badge
                variant="outline"
                className={cn('text-xs', REVIEW_DUE_BADGE_CLASS)}
                data-testid="review-due"
              >
                Review due
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading review state
          </div>
        ) : (
          <>
            <dl className="space-y-1 text-sm">
              <div className="flex gap-2">
                <dt className="w-20 shrink-0 text-muted-foreground">Reviewed</dt>
                <dd>
                  {reviewState?.reviewedAt
                    ? `${formatReviewDate(reviewState.reviewedAt)} by ${reviewState.reviewerEmail ?? 'unknown'}`
                    : 'Not yet'}
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-20 shrink-0 text-muted-foreground">Approved</dt>
                <dd>
                  {hasApproval && reviewState?.approvedAt
                    ? `${formatReviewDate(reviewState.approvedAt)} by ${reviewState.approverEmail ?? 'unknown'}`
                    : 'Not yet'}
                </dd>
              </div>
              {approvalState === 'changed' && (
                <p className="text-xs text-amber-700">
                  The content differs from what was approved. Approve again or undo the change.
                </p>
              )}
              {reviewState?.reviewDue && reviewState.validUntil && (
                <p className="text-xs text-red-700">
                  Review due since {formatReviewDate(reviewState.validUntil)}.
                </p>
              )}
            </dl>

            {sourceApproval && (
              <p className="text-xs text-muted-foreground border-l-2 pl-2" data-testid="source-document-approval">
                {sourceApproval.approverName || sourceApproval.approvedAt
                  ? `Approved in the source document by ${sourceApproval.approverName ?? 'an unnamed party'}${
                      sourceApproval.approvedAt ? ` on ${formatReviewDate(sourceApproval.approvedAt)}` : ''
                    }.`
                  : `Reviewed in the source document by ${sourceApproval.reviewerName ?? 'an unnamed party'}${
                      sourceApproval.reviewedAt ? ` on ${formatReviewDate(sourceApproval.reviewedAt)}` : ''
                    }.`}
                {' '}This is history, not an approval of this model.
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1 text-xs"
                onClick={handleMarkReviewed}
                disabled={markReviewedMutation.isPending}
              >
                <ClipboardCheck className="h-3 w-3" />
                Mark reviewed
              </Button>
              <Button
                size="sm"
                className="h-7 gap-1 text-xs"
                onClick={() => setSignOffOpen(true)}
                disabled={!isSecurityTeam || approveMutation.isPending || approvalState === 'approved'}
                title={securityTeamHint}
              >
                <ShieldCheck className="h-3 w-3" />
                {approvalState === 'changed' ? 'Approve again' : 'Approve'}
              </Button>
              {hasApproval && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 text-xs"
                  onClick={handleRevoke}
                  disabled={!isSecurityTeam || revokeMutation.isPending}
                  title={securityTeamHint}
                >
                  <Undo2 className="h-3 w-3" />
                  Revoke
                </Button>
              )}
              {securityTeamHint && (
                <span className="text-xs text-muted-foreground">{securityTeamHint}</span>
              )}
            </div>

            <div>
              <button
                type="button"
                className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
                onClick={() => setAdvancedOpen((open) => !open)}
                aria-expanded={advancedOpen}
              >
                {advancedOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Advanced
              </button>
              {advancedOpen && (
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs" htmlFor="review-lifecycle-phase">
                      Lifecycle phase
                    </Label>
                    <Select
                      value={reviewState?.lifecyclePhase || LIFECYCLE_NONE}
                      onValueChange={(value) =>
                        saveField({ lifecyclePhase: value === LIFECYCLE_NONE ? '' : (value as LifecyclePhase) })
                      }
                    >
                      <SelectTrigger id="review-lifecycle-phase" className="h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={LIFECYCLE_NONE}>Not set</SelectItem>
                        {LIFECYCLE_PHASES.map((phase) => (
                          <SelectItem key={phase.value} value={phase.value}>
                            {phase.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs" htmlFor="review-frequency">
                      Review frequency
                    </Label>
                    <Select value={frequencyPreset} onValueChange={handleFrequencyPresetChange}>
                      <SelectTrigger id="review-frequency" className="h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={REVIEW_FREQUENCY_NONE}>Not set</SelectItem>
                        {REVIEW_FREQUENCY_PRESETS.map((preset) => (
                          <SelectItem key={preset.value} value={preset.value}>
                            {preset.label}
                          </SelectItem>
                        ))}
                        <SelectItem value={REVIEW_FREQUENCY_CUSTOM}>Custom (ISO 8601)</SelectItem>
                      </SelectContent>
                    </Select>
                    {frequencyPreset === REVIEW_FREQUENCY_CUSTOM && (
                      <div className="flex gap-1">
                        <Input
                          className="h-8 text-xs"
                          value={customFrequency}
                          onChange={(event) => setCustomDraft(event.target.value)}
                          placeholder="P2W"
                          aria-label="Custom review frequency"
                        />
                        <Button size="sm" className="h-8 text-xs" onClick={handleCustomFrequencySave}>
                          Save
                        </Button>
                      </div>
                    )}
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs" htmlFor="review-valid-from">
                      Valid from
                    </Label>
                    <Input
                      id="review-valid-from"
                      type="date"
                      className="h-8 text-xs"
                      value={dateInputValue(reviewState?.validFrom)}
                      onChange={(event) => saveField({ validFrom: dateInputToIso(event.target.value) })}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs" htmlFor="review-valid-until">
                      Valid until
                    </Label>
                    <Input
                      id="review-valid-until"
                      type="date"
                      className="h-8 text-xs"
                      value={dateInputValue(reviewState?.validUntil)}
                      onChange={(event) => saveField({ validUntil: dateInputToIso(event.target.value) })}
                    />
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </CardContent>

      <ApproveSignOffDialog
        open={signOffOpen}
        onOpenChange={setSignOffOpen}
        threatModelId={threatModelId}
        threatModelName={threatModelName}
        onConfirm={handleApprove}
        isApproving={approveMutation.isPending}
      />
    </Card>
  )
}
