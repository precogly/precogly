import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportCountermeasureSummary, ReportThreat } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import { countermeasureStatusLabel, targetsText } from '../utils/labels'
import { buildCountermeasureDetailRows } from '../utils/countermeasureRows'
import { ReportSection } from '../ReportSection'

interface CountermeasureSectionProps {
  summary: ReportCountermeasureSummary
  depth: SectionDepth
  sectionId: string
  /** The active scenarios, for the per-control detail table. */
  threats?: ReportThreat[]
}

const CM_STATUS_COLORS: Record<string, string> = {
  gap: 'border-l-red-500',
  planned: 'border-l-yellow-500',
  in_progress: 'border-l-orange-500',
  implemented: 'border-l-emerald-500',
  verified: 'border-l-green-500',
  platform: 'border-l-green-600',
  waived: 'border-l-blue-500',
  decommissioned: 'border-l-gray-400',
}

function StatusOverview({ summary }: { summary: ReportCountermeasureSummary }) {
  const totalControls = Object.values(summary.statusBreakdown).reduce((sum, count) => sum + count, 0)
  const unattachedCount = summary.unattached.length

  return (
    <ReportSection title="Countermeasure Status">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Object.entries(summary.statusBreakdown).map(([status, count]) => (
          <Card key={status} className={`border-l-4 ${CM_STATUS_COLORS[status] || ''}`}>
            <CardContent className="pt-3 pb-3">
              <div className="text-xl font-bold">{count}</div>
              <div className="text-xs text-muted-foreground">{countermeasureStatusLabel(status)}</div>
            </CardContent>
          </Card>
        ))}
      </div>
      {totalControls > 0 && (
        <div className="mt-2 text-sm text-muted-foreground">
          Total: {totalControls} controls
          {unattachedCount > 0 && (
            <>
              , of which {unattachedCount} not linked to any threat (left out of gap and coverage figures)
            </>
          )}
        </div>
      )}
    </ReportSection>
  )
}

function GapsSection({ summary, depth }: { summary: ReportCountermeasureSummary; depth: SectionDepth }) {
  const gaps = depth === 'top3' ? summary.gaps.slice(0, 3) : summary.gaps
  const title = depth === 'top3' ? 'Top Gaps' : `Gaps (${summary.gaps.length})`

  if (gaps.length === 0) {
    return (
      <ReportSection title={depth === 'top3' ? 'Top Gaps' : 'Gaps'}>
        <p className="text-sm text-muted-foreground">No open gaps.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={title}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Countermeasure</TableHead>
            <TableHead>Threat</TableHead>
            <TableHead>Targets</TableHead>
            <TableHead>Priority</TableHead>
            <TableHead>Owner</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {gaps.map((gap) => (
            <TableRow key={gap.id}>
              <TableCell className="font-mono text-xs font-semibold">{gap.controlNumber}</TableCell>
              <TableCell className="font-medium">{gap.countermeasureName}</TableCell>
              <TableCell className="font-mono text-xs">{gap.displayNumber ?? ''}</TableCell>
              <TableCell>{targetsText(gap.targets)}</TableCell>
              <TableCell>{gap.priority ? <Badge variant="outline">{gap.priority}</Badge> : ''}</TableCell>
              <TableCell>{gap.assignedOwnerEmail || 'Unassigned'}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {depth === 'top3' && summary.gaps.length > 3 && (
        <p className="mt-2 text-sm text-muted-foreground">+ {summary.gaps.length - 3} more gaps</p>
      )}
    </ReportSection>
  )
}

function WaivedSection({ summary, depth }: { summary: ReportCountermeasureSummary; depth: SectionDepth }) {
  if (depth === 'count') {
    return (
      <ReportSection title="Waived Countermeasures">
        <p className="text-sm">
          <span className="font-bold text-lg">{summary.waived.length}</span>{' '}
          <span className="text-muted-foreground">countermeasures waived</span>
        </p>
      </ReportSection>
    )
  }

  if (summary.waived.length === 0) {
    return (
      <ReportSection title="Waived Countermeasures">
        <p className="text-sm text-muted-foreground">No waived countermeasures.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Waived Countermeasures (${summary.waived.length})`}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Countermeasure</TableHead>
            <TableHead>Threat</TableHead>
            <TableHead>Targets</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {summary.waived.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-mono text-xs font-semibold">{item.controlNumber}</TableCell>
              <TableCell className="font-medium">{item.countermeasureName}</TableCell>
              <TableCell className="font-mono text-xs">{item.displayNumber ?? ''}</TableCell>
              <TableCell>{targetsText(item.targets)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}

/** Controls with no threat link (I3): their own block, out of gap and coverage figures. */
function UnattachedSection({ summary }: { summary: ReportCountermeasureSummary }) {
  if (summary.unattached.length === 0) {
    return (
      <ReportSection title="Controls not linked to any threat" defaultOpen={false}>
        <p className="text-sm text-muted-foreground">Every control is linked to a threat.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Controls not linked to any threat (${summary.unattached.length})`}>
      <p className="text-xs text-muted-foreground mb-2">
        Not counted in coverage or gap figures. Link each one to a threat or remove it.
      </p>
      <Table data-testid="report-unattached-table">
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Countermeasure</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Applies to</TableHead>
            <TableHead>Origin</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {summary.unattached.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-mono text-xs font-semibold">{item.controlNumber}</TableCell>
              <TableCell className="font-medium">{item.countermeasureName}</TableCell>
              <TableCell>{countermeasureStatusLabel(item.status)}</TableCell>
              <TableCell>{targetsText(item.scope)}</TableCell>
              <TableCell className="text-muted-foreground">{item.autoGenerated ? 'Generated' : 'Added by hand'}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}

/** Each control once: number, status, scope (applies to), provider and source (plan 11.6). */
function DetailSection({ threats }: { threats: ReportThreat[] }) {
  const rows = buildCountermeasureDetailRows(threats)

  if (rows.length === 0) {
    return (
      <ReportSection title="Countermeasure Detail">
        <p className="text-sm text-muted-foreground">No countermeasures linked to a threat.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Countermeasure Detail (${rows.length})`}>
      <Table data-testid="report-countermeasure-table">
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Countermeasure</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Threats</TableHead>
            <TableHead>Applies to</TableHead>
            <TableHead>Implemented by</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Owner</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.id} data-testid="report-countermeasure-row">
              <TableCell className="font-mono text-xs font-semibold align-top">{row.displayNumber}</TableCell>
              <TableCell className="align-top">
                <div className="font-medium">{row.countermeasureName}</div>
                {row.controlFunctions.length > 0 && (
                  <div className="text-xs text-muted-foreground capitalize">{row.controlFunctions.join(', ')}</div>
                )}
                {row.complianceStandards.length > 0 && (
                  <div className="text-[10px] text-muted-foreground">{row.complianceStandards.join(', ')}</div>
                )}
              </TableCell>
              <TableCell className="align-top">
                <Badge variant="outline">{countermeasureStatusLabel(row.status)}</Badge>
              </TableCell>
              <TableCell className="font-mono text-xs align-top">{row.threatNumbers.join(', ')}</TableCell>
              <TableCell className="align-top">{targetsText(row.scope)}</TableCell>
              <TableCell className="align-top">{row.implementedByParty || ''}</TableCell>
              <TableCell className="align-top text-muted-foreground">{row.source || ''}</TableCell>
              <TableCell className="align-top">{row.assignedOwnerEmail || ''}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}

export function CountermeasureSection({ summary, depth, sectionId, threats = [] }: CountermeasureSectionProps) {
  switch (sectionId) {
    case 'countermeasureStatus':
      return <StatusOverview summary={summary} />
    case 'countermeasureDetail':
      return <DetailSection threats={threats} />
    case 'gaps':
      return <GapsSection summary={summary} depth={depth} />
    case 'waived':
      return <WaivedSection summary={summary} depth={depth} />
    case 'unattached':
      return <UnattachedSection summary={summary} />
    default:
      return null
  }
}
