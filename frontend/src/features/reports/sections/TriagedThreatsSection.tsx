import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportTriagedThreat } from '@/features/reports/types/report'
import { targetsText } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface TriagedThreatsSectionProps {
  triagedThreats: ReportTriagedThreat[]
}

const TRIAGE_LABELS: Record<string, string> = {
  accept: 'Accepted',
  delegate: 'Delegated',
  eliminate: 'Eliminated',
  mitigate: 'Mitigate',
  open: 'Open',
}

export function TriagedThreatsSection({ triagedThreats }: TriagedThreatsSectionProps) {
  if (triagedThreats.length === 0) {
    return (
      <ReportSection title="Triaged Threats" defaultOpen={false}>
        <p className="text-sm text-muted-foreground">No triaged threats.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Triaged Threats (${triagedThreats.length})`} defaultOpen={false}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Threat</TableHead>
            <TableHead>Targets</TableHead>
            <TableHead>Decision</TableHead>
            <TableHead>Rationale</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {triagedThreats.map((threat) => (
            <TableRow key={threat.id}>
              <TableCell className="font-mono text-xs font-semibold">{threat.displayNumber}</TableCell>
              <TableCell className="font-medium">{threat.threatName}</TableCell>
              <TableCell>{targetsText(threat.targets)}</TableCell>
              <TableCell>
                <Badge variant="outline">{TRIAGE_LABELS[threat.triageStatus] ?? threat.triageStatus}</Badge>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">{threat.decisionRationale}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
