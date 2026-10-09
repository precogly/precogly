import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import type { ReportData } from '@/features/reports/types/report'
import { RATING_LEVEL_CLASSES, ratingLevelLabel } from '@/features/threat-models/components/rating/rating-utils'
import { RATING_LEVELS } from '@/types/risk'
import { THREAT_STATUS_CONFIG } from '@/features/dfd-editor/types/threat-analysis'
import { approvalStateLabel, methodologyNameLabel, threatStatusLabel } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ExecutiveSummaryProps {
  data: ReportData
}

const CRITICALITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
}

const APPROVAL_STATE_COLORS: Record<string, string> = {
  none: 'bg-gray-100 text-gray-700',
  approved: 'bg-green-100 text-green-700',
  changed: 'bg-yellow-100 text-yellow-700',
  review_due: 'bg-orange-100 text-orange-700',
}

function threatStatusClass(status: string): string {
  return THREAT_STATUS_CONFIG[status as keyof typeof THREAT_STATUS_CONFIG]?.bgColor ?? 'bg-gray-100 text-gray-700'
}

export function ExecutiveSummary({ data }: ExecutiveSummaryProps) {
  const { metadata, summaryMetrics } = data
  // Worst level first, `info` last, so the badges read like the register.
  const levelsWithRisks = [...RATING_LEVELS]
    .reverse()
    .filter((level) => (summaryMetrics.risksByLevel[level.value] ?? 0) > 0)

  return (
    <ReportSection title="Executive Summary">
      <div className="space-y-6">
        <div className="flex flex-wrap gap-2">
          <Badge className={CRITICALITY_COLORS[metadata.criticality] || ''}>{metadata.criticality} criticality</Badge>
          <Badge className={APPROVAL_STATE_COLORS[metadata.review.approvalState] || ''}>
            {approvalStateLabel(metadata.review.approvalState)}
          </Badge>
          {metadata.methodologies.map((methodology) => (
            <Badge key={methodology} variant="outline">
              {methodologyNameLabel(methodology)}
            </Badge>
          ))}
          {metadata.frameworks.map((framework) => (
            <Badge key={framework.slug} variant="secondary">
              {framework.name}
            </Badge>
          ))}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{summaryMetrics.totalActiveThreats}</div>
              <div className="text-sm text-muted-foreground">Active Threats</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{summaryMetrics.totalCountermeasures}</div>
              <div className="text-sm text-muted-foreground">Countermeasures</div>
              {summaryMetrics.totalUnattached > 0 && (
                <div className="text-xs text-muted-foreground">{summaryMetrics.totalUnattached} not linked to a threat</div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-red-600">{summaryMetrics.totalGaps}</div>
              <div className="text-sm text-muted-foreground">Open Gaps</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{summaryMetrics.totalRisks}</div>
              <div className="text-sm text-muted-foreground">Risks</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="font-medium mb-2">Threats by Status</h4>
            <div className="flex flex-wrap gap-2">
              {Object.entries(summaryMetrics.threatsByStatus).map(([status, count]) => (
                <Badge key={status} className={threatStatusClass(status)}>
                  {threatStatusLabel(status)}: {count}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <h4 className="font-medium mb-2">Risks by Level</h4>
            <div className="flex flex-wrap gap-2">
              {levelsWithRisks.length === 0 && <span className="text-sm text-muted-foreground">No rated risks.</span>}
              {levelsWithRisks.map((level) => (
                <Badge key={level.value} variant="outline" className={RATING_LEVEL_CLASSES[level.value]}>
                  {ratingLevelLabel(level.value)}: {summaryMetrics.risksByLevel[level.value]}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </div>
    </ReportSection>
  )
}
