import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { BUSINESS_OBJECTIVE_CRITICALITIES } from '@/types/domain'
import type { ReportBusinessObjective } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import { ReportSection } from '../ReportSection'

interface BusinessObjectivesSectionProps {
  objectives: ReportBusinessObjective[]
  depth: SectionDepth
}

const CRITICALITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  moderate: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  minimal: 'bg-slate-100 text-slate-700',
}

function criticalityLabel(value: string): string {
  return BUSINESS_OBJECTIVE_CRITICALITIES.find((entry) => entry.value === value)?.label ?? value
}

/** The objectives the model protects, with how many threats and risks point at each (plan 11.6). */
export function BusinessObjectivesSection({ objectives, depth }: BusinessObjectivesSectionProps) {
  if (objectives.length === 0) {
    return (
      <ReportSection title="Business objectives" defaultOpen={false}>
        <p className="text-sm text-muted-foreground">No business objectives recorded.</p>
      </ReportSection>
    )
  }

  if (depth === 'summary') {
    return (
      <ReportSection title={`Business objectives (${objectives.length})`}>
        <ul className="space-y-1 text-sm">
          {objectives.map((objective) => (
            <li key={objective.id} className="flex items-center gap-2">
              <span className="font-medium">{objective.name}</span>
              <Badge className={CRITICALITY_COLORS[objective.criticality] || ''}>
                {criticalityLabel(objective.criticality)}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {objective.threatCount} threats, {objective.riskCount} risks
              </span>
            </li>
          ))}
        </ul>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Business objectives (${objectives.length})`}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Objective</TableHead>
            <TableHead>Criticality</TableHead>
            <TableHead>Owner</TableHead>
            <TableHead className="text-right">Threats</TableHead>
            <TableHead className="text-right">Risks</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {objectives.map((objective) => (
            <TableRow key={objective.id}>
              <TableCell>
                <div className="font-medium">{objective.name}</div>
                {objective.description && (
                  <div className="text-xs text-muted-foreground">{objective.description}</div>
                )}
              </TableCell>
              <TableCell>
                <Badge className={CRITICALITY_COLORS[objective.criticality] || ''}>
                  {criticalityLabel(objective.criticality)}
                </Badge>
              </TableCell>
              <TableCell>{objective.owner}</TableCell>
              <TableCell className="text-right">{objective.threatCount}</TableCell>
              <TableCell className="text-right">{objective.riskCount}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
