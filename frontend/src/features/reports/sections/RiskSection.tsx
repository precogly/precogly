import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { ReportRisk, ReportRiskResponse } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import { ReportRatingBadge } from '../components/ReportRatingBadge'
import {
  formatReportDate,
  responseStatusLabel,
  responseStrategyLabel,
  riskDomainLabel,
  riskExposureLabel,
  riskStatusLabel,
  targetsText,
  threatStatusLabel,
} from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface RiskSectionProps {
  risks: ReportRisk[]
  depth: SectionDepth
}

const EXPOSURE_COLORS: Record<string, string> = {
  exposed: 'bg-red-100 text-red-700',
  addressable: 'bg-yellow-100 text-yellow-700',
  mitigated: 'bg-green-100 text-green-700',
}

function ResponsesTable({ responses }: { responses: ReportRiskResponse[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Strategy</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Owner</TableHead>
          <TableHead>Target date</TableHead>
          <TableHead>Controls</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {responses.map((response) => (
          <TableRow key={response.id}>
            <TableCell className="font-medium">{responseStrategyLabel(response.strategy)}</TableCell>
            <TableCell className="text-sm">{response.description}</TableCell>
            <TableCell>
              <Badge variant="outline">{responseStatusLabel(response.status)}</Badge>
            </TableCell>
            <TableCell>{response.ownerEmail || ''}</TableCell>
            <TableCell>{formatReportDate(response.targetDate)}</TableCell>
            <TableCell className="font-mono text-xs">{response.countermeasures.join(', ')}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function RiskRow({ risk, depth }: { risk: ReportRisk; depth: SectionDepth }) {
  const [expanded, setExpanded] = useState(false)
  const expandable = depth === 'full'

  return (
    <>
      <TableRow
        className={expandable ? 'cursor-pointer hover:bg-muted/50' : ''}
        onClick={() => expandable && setExpanded(!expanded)}
      >
        <TableCell>
          <div className="flex items-center gap-1">
            {expandable && (expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />)}
            <span className="font-medium">{risk.name}</span>
          </div>
          {risk.domains.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {risk.domains.map((domain) => (
                <Badge key={domain} variant="outline" className="text-[10px]">
                  {riskDomainLabel(domain)}
                </Badge>
              ))}
            </div>
          )}
        </TableCell>
        <TableCell>
          <Badge variant="outline">{riskStatusLabel(risk.status)}</Badge>
        </TableCell>
        <TableCell>
          <Badge className={EXPOSURE_COLORS[risk.exposure] || ''}>{riskExposureLabel(risk.exposure)}</Badge>
        </TableCell>
        <TableCell>
          <ReportRatingBadge rating={risk.inherent} />
        </TableCell>
        <TableCell>
          <ReportRatingBadge rating={risk.residual} />
        </TableCell>
        <TableCell>
          <ReportRatingBadge rating={risk.target} />
        </TableCell>
        <TableCell>{risk.ownerEmail || ''}</TableCell>
      </TableRow>
      {expanded && expandable && (
        <TableRow>
          <TableCell colSpan={7} className="bg-muted/30">
            <div className="space-y-3 py-1">
              {risk.statement && (
                <div>
                  <span className="text-xs font-medium">Statement</span>
                  <p className="text-sm">{risk.statement}</p>
                </div>
              )}
              {risk.description && <p className="text-sm text-muted-foreground">{risk.description}</p>}
              {risk.businessObjectives.length > 0 && (
                <div>
                  <span className="text-xs font-medium">Business objectives</span>
                  <p className="text-sm">{risk.businessObjectives.join(', ')}</p>
                </div>
              )}
              {risk.contributingThreats.length > 0 && (
                <div>
                  <span className="text-xs font-medium">Contributing threats</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {risk.contributingThreats.map((threat) => (
                      <Badge key={threat.threatId} variant="outline" className="text-xs">
                        <span className="font-mono mr-1">{threat.displayNumber}</span>
                        {threat.threatName} ({threatStatusLabel(threat.status)})
                        {threat.targets.length > 0 && (
                          <span className="text-muted-foreground ml-1">on {targetsText(threat.targets)}</span>
                        )}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {risk.responses.length > 0 && (
                <div>
                  <span className="text-xs font-medium">Responses ({risk.responses.length})</span>
                  <ResponsesTable responses={risk.responses} />
                </div>
              )}
              {(risk.inherent?.rationale || risk.residual?.rationale) && (
                <div className="text-xs text-muted-foreground">
                  {risk.inherent?.rationale && <p>Inherent: {risk.inherent.rationale}</p>}
                  {risk.residual?.rationale && <p>Residual: {risk.residual.rationale}</p>}
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

export function RiskSection({ risks, depth }: RiskSectionProps) {
  if (risks.length === 0) {
    return (
      <ReportSection title="Risk Register">
        <p className="text-sm text-muted-foreground">No risks defined.</p>
      </ReportSection>
    )
  }

  return (
    <ReportSection title={`Risk Register (${risks.length})`}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Risk</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Exposure</TableHead>
            <TableHead>Inherent</TableHead>
            <TableHead>Residual</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Owner</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {risks.map((risk) => (
            <RiskRow key={risk.id} risk={risk} depth={depth} />
          ))}
        </TableBody>
      </Table>
    </ReportSection>
  )
}
