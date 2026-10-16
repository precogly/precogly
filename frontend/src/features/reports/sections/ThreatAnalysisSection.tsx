import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import type { ReportThreatAnalysis } from '@/features/reports/types/report'
import { THREAT_STATUS_CONFIG } from '@/features/dfd-editor/types/threat-analysis'
import { ReportRatingBadge } from '../components/ReportRatingBadge'
import { countermeasureStatusLabel, targetsText, threatStatusLabel } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ThreatAnalysisSectionProps {
  threatAnalysis: ReportThreatAnalysis
}

const CM_STATUS_COLORS: Record<string, string> = {
  gap: 'bg-red-100 text-red-700',
  planned: 'bg-yellow-100 text-yellow-700',
  in_progress: 'bg-orange-100 text-orange-700',
  implemented: 'bg-emerald-100 text-emerald-700',
  verified: 'bg-green-100 text-green-700',
  platform: 'bg-green-100 text-green-700',
  waived: 'bg-blue-100 text-blue-700',
}

function threatStatusClass(status: string): string {
  return THREAT_STATUS_CONFIG[status as keyof typeof THREAT_STATUS_CONFIG]?.bgColor ?? 'bg-gray-100 text-gray-700'
}

/**
 * One row per scenario (plan 11.6): its number, its targets, the rating as a
 * badge and its controls by number. A threat on several targets appears once;
 * a whole-system threat says so.
 */
export function ThreatAnalysisSection({ threatAnalysis }: ThreatAnalysisSectionProps) {
  const { threats } = threatAnalysis

  if (threats.length === 0) {
    return (
      <ReportSection title="Threat Detail">
        <p className="text-sm text-muted-foreground">No active threats.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Threat Detail (${threats.length})`}>
      <Table data-testid="report-threat-table">
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Threat</TableHead>
            <TableHead>Targets</TableHead>
            <TableHead>Classifications</TableHead>
            <TableHead>Rating</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Controls</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {threats.map((threat) => (
            <TableRow key={threat.id} data-testid="report-threat-row">
              <TableCell className="font-mono text-xs font-semibold align-top">{threat.displayNumber}</TableCell>
              <TableCell className="align-top">
                <div className="font-medium text-sm">{threat.threatName}</div>
                {threat.threatDescription && (
                  <div className="text-xs text-muted-foreground line-clamp-2">{threat.threatDescription}</div>
                )}
                {threat.businessObjectives.length > 0 && (
                  <div className="text-[11px] text-muted-foreground mt-1">
                    Objectives: {threat.businessObjectives.join(', ')}
                  </div>
                )}
              </TableCell>
              <TableCell className="text-sm align-top">
                {threat.wholeSystem ? (
                  <span className="italic">Whole system</span>
                ) : (
                  targetsText(threat.targets)
                )}
              </TableCell>
              <TableCell className="align-top">
                <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={3} size="sm" />
              </TableCell>
              <TableCell className="align-top">
                <ReportRatingBadge rating={threat.rating} />
              </TableCell>
              <TableCell className="align-top">
                <Badge className={threatStatusClass(threat.status)}>{threatStatusLabel(threat.status)}</Badge>
              </TableCell>
              <TableCell className="align-top">
                {threat.countermeasures.length === 0 ? (
                  <span className="text-xs text-muted-foreground">None</span>
                ) : (
                  <div className="flex flex-col gap-1">
                    {threat.countermeasures.map((countermeasure) => (
                      <div key={countermeasure.id} className="flex flex-col">
                        <Badge
                          variant="outline"
                          className={`text-xs justify-start ${CM_STATUS_COLORS[countermeasure.status] || ''}`}
                        >
                          <span className="font-mono mr-1">{countermeasure.displayNumber}</span>
                          {countermeasure.countermeasureName}: {countermeasureStatusLabel(countermeasure.status)}
                        </Badge>
                        {countermeasure.complianceStandards && countermeasure.complianceStandards.length > 0 && (
                          <span className="text-[10px] text-muted-foreground ml-1">
                            {countermeasure.complianceStandards
                              .map((standard) => `${standard.frameworkName} ${standard.sectionCode}`)
                              .join(', ')}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
