import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportAssumption, ReportScope } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import { ASSUMPTION_VALIDITY_COLORS, assumptionTopicLabel, assumptionValidityLabel, formatReportDate } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface AssumptionsReviewSectionProps {
  scope: ReportScope
  depth: SectionDepth
}

/** The assumptions that still need a reviewer's attention: anything not verified. */
function flaggedAssumptions(assumptions: readonly ReportAssumption[]): ReportAssumption[] {
  return assumptions.filter((assumption) => assumption.validity !== 'verified')
}

export function AssumptionsReviewSection({ scope, depth }: AssumptionsReviewSectionProps) {
  const assumptions = depth === 'flagged' ? flaggedAssumptions(scope.assumptions) : scope.assumptions

  if (assumptions.length === 0) {
    return (
      <ReportSection title="Assumptions Review">
        <p className="text-sm text-muted-foreground">
          {depth === 'flagged' ? 'All assumptions verified.' : 'No assumptions defined.'}
        </p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Assumptions Review (${assumptions.length})`}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Validity</TableHead>
            <TableHead>Assumption</TableHead>
            <TableHead>Topic</TableHead>
            <TableHead>Owner</TableHead>
            <TableHead>Validation</TableHead>
            <TableHead>Components</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {assumptions.map((assumption) => (
            <TableRow key={assumption.id}>
              <TableCell className="align-top">
                <Badge className={ASSUMPTION_VALIDITY_COLORS[assumption.validity] || ''}>
                  {assumptionValidityLabel(assumption.validity)}
                </Badge>
              </TableCell>
              <TableCell className="text-sm align-top">
                {assumption.description}
                {assumption.impact && (
                  <div className="text-xs text-muted-foreground mt-0.5">Impact if invalid: {assumption.impact}</div>
                )}
              </TableCell>
              <TableCell className="align-top">{assumptionTopicLabel(assumption.topic)}</TableCell>
              <TableCell className="text-sm align-top">{assumption.owner}</TableCell>
              <TableCell className="text-xs text-muted-foreground align-top">
                {[assumption.validationMethod, formatReportDate(assumption.validationDate)].filter(Boolean).join(', ')}
              </TableCell>
              <TableCell className="text-xs align-top">{assumption.components.join(', ')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
