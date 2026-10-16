import { Badge } from '@/components/ui/badge'
import type { ReportAssumption, ReportMetadata } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import {
  approvalStateLabel,
  assumptionValidityLabel,
  formatReportDate,
  lifecyclePhaseLabel,
  reviewFrequencyLabel,
} from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ReviewSectionProps {
  metadata: ReportMetadata
  assumptions: ReportAssumption[]
  depth: SectionDepth
}

const APPROVAL_STATE_COLORS: Record<string, string> = {
  none: 'bg-gray-100 text-gray-700',
  approved: 'bg-green-100 text-green-700',
  changed: 'bg-yellow-100 text-yellow-700',
}

const REVIEW_DUE_COLOR = 'bg-orange-100 text-orange-700'

/** "2 verified, 2 unverified, 1 invalid" in a fixed order; the empty string with no assumptions. */
function assumptionValiditySummary(assumptions: readonly ReportAssumption[]): string {
  const counts = new Map<string, number>()
  for (const assumption of assumptions) {
    counts.set(assumption.validity, (counts.get(assumption.validity) ?? 0) + 1)
  }
  return ['verified', 'unverified', 'unknown', 'invalid']
    .filter((validity) => (counts.get(validity) ?? 0) > 0)
    .map((validity) => `${counts.get(validity)} ${assumptionValidityLabel(validity).toLowerCase()}`)
    .join(', ')
}

function personAndDate(person: string | null, date: string | null): string {
  if (!person && !date) return 'Not yet'
  return [person, formatReportDate(date)].filter(Boolean).join(', ')
}

/**
 * Review and approval (plan 11.6, mockup 08): reviewer and approver with
 * dates, the derived state, then lifecycle phase, validity window and review
 * frequency. An approval that came with an imported document is history, not
 * an approval of this model (D18).
 */
export function ReviewSection({ metadata, assumptions, depth }: ReviewSectionProps) {
  const { review } = metadata
  const validitySummary = assumptionValiditySummary(assumptions)
  const validityWindow = [
    metadata.validFrom ? `from ${formatReportDate(metadata.validFrom)}` : '',
    metadata.validUntil ? `until ${formatReportDate(metadata.validUntil)}` : '',
  ]
    .filter(Boolean)
    .join(' ')
  const sourceReview = review.sourceDocumentReview

  return (
    <ReportSection title="Review and approval">
      <div className="space-y-3 text-sm" data-testid="report-review">
        <div className="flex items-center gap-2">
          <Badge className={APPROVAL_STATE_COLORS[review.approvalState] || ''}>
            {approvalStateLabel(review.approvalState)}
          </Badge>
          {review.reviewDue && <Badge className={REVIEW_DUE_COLOR}>Review due</Badge>}
          {validityWindow && <span className="text-muted-foreground">Valid {validityWindow}</span>}
        </div>

        <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1">
          <dt className="text-muted-foreground">Reviewed by</dt>
          <dd>{personAndDate(review.reviewer, review.reviewedAt)}</dd>
          <dt className="text-muted-foreground">Approved by</dt>
          <dd>{personAndDate(review.approver, review.approvedAt)}</dd>
          <dt className="text-muted-foreground">Lifecycle phase</dt>
          <dd>{lifecyclePhaseLabel(metadata.lifecyclePhase) || 'Not set'}</dd>
          {depth === 'full' && (
            <>
              <dt className="text-muted-foreground">Review frequency</dt>
              <dd>{reviewFrequencyLabel(metadata.reviewFrequency) || 'Not set'}</dd>
              <dt className="text-muted-foreground">Last updated</dt>
              <dd>{formatReportDate(metadata.updatedAt) || 'Unknown'}</dd>
            </>
          )}
        </dl>

        {validitySummary && <p className="text-muted-foreground">Assumptions: {validitySummary}.</p>}

        {sourceReview && Object.keys(sourceReview).length > 0 && (
          <div className="rounded border bg-muted/30 p-2 text-xs">
            <div className="font-medium mb-1">Approved in the source document (history)</div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
              {Object.entries(sourceReview).map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-muted-foreground">{key}</dt>
                  <dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>
    </ReportSection>
  )
}
