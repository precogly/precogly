/**
 * The compliance matrix (idea from PR #561 by JJediny): for each framework
 * the model's countermeasures map to, one row per requirement with its state,
 * the countermeasures that map to it, their threats and an overdue mark.
 * Framework-neutral: the user picks the framework; nothing defaults to one.
 * Coverage is stated against the installed pack, which may hold only part of
 * a standard.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { COUNTERMEASURE_STATUS_CONFIG, type CountermeasureStatus } from '@/features/dfd-editor/types/threat-analysis'
import type { ComplianceMatrixFramework, ComplianceMatrixState } from '@/features/reports/types/report'
import { ReportSection } from '../ReportSection'
import {
  MATRIX_STATES,
  MATRIX_STATE_DESCRIPTIONS,
  MATRIX_STATE_LABELS,
  frameworkCoverageLine,
  rowThreatNumbers,
  stateCount,
  visibleMatrixGroups,
} from '../utils/complianceMatrix'

const STATE_CLASSES: Record<ComplianceMatrixState, string> = {
  satisfied: 'border-green-300 bg-green-50 text-green-800',
  covered: 'border-blue-300 bg-blue-50 text-blue-800',
  partial_only: 'border-amber-300 bg-amber-50 text-amber-800',
  not_covered: 'border-red-300 bg-red-50 text-red-800',
}

function StateBadge({ state, count }: { state: ComplianceMatrixState; count?: number }) {
  return (
    <Badge
      variant="outline"
      className={cn('whitespace-nowrap text-xs font-normal', STATE_CLASSES[state])}
      title={MATRIX_STATE_DESCRIPTIONS[state]}
    >
      {MATRIX_STATE_LABELS[state]}
      {count !== undefined && <span className="ml-1 font-semibold">{count}</span>}
    </Badge>
  )
}

function statusLabel(status: string): string {
  return COUNTERMEASURE_STATUS_CONFIG[status as CountermeasureStatus]?.label ?? status
}

interface ComplianceMatrixSectionProps {
  matrix: ComplianceMatrixFramework[] | undefined
  threatModelId: string
}

export function ComplianceMatrixSection({ matrix = [], threatModelId }: ComplianceMatrixSectionProps) {
  const [frameworkIndex, setFrameworkIndex] = useState(0)
  const [showNotCovered, setShowNotCovered] = useState(true)

  if (matrix.length === 0) {
    return (
      <ReportSection title="Compliance Matrix">
        <p className="text-sm text-muted-foreground">
          No countermeasure maps to a framework requirement yet. Map one in its countermeasure dialog, under Compliance
          coverage.
        </p>
      </ReportSection>
    )
  }

  const framework = matrix[Math.min(frameworkIndex, matrix.length - 1)]
  const groups = visibleMatrixGroups(framework, showNotCovered)

  return (
    <ReportSection title="Compliance Matrix">
      <div className="space-y-3" data-testid="compliance-matrix">
        <div className="flex flex-wrap items-center gap-3">
          {matrix.length > 1 ? (
            <Select value={String(frameworkIndex)} onValueChange={(value) => setFrameworkIndex(Number(value))}>
              <SelectTrigger className="h-8 w-[280px] text-sm" aria-label="Framework">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {matrix.map((entry, index) => (
                  <SelectItem key={`${entry.name}-${entry.version}`} value={String(index)}>
                    {entry.name} {entry.version}
                    {!entry.installed && ' (not installed)'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <span className="text-sm font-medium">
              {framework.name} {framework.version}
            </span>
          )}
          <div className="flex flex-wrap items-center gap-1.5" data-testid="compliance-matrix-counts">
            {MATRIX_STATES.filter((state) => framework.installed || state !== 'not_covered').map((state) => (
              <StateBadge key={state} state={state} count={stateCount(framework, state)} />
            ))}
          </div>
          {framework.installed && (
            <div className="flex items-center gap-1.5">
              <Checkbox
                id="matrix-show-not-covered"
                checked={showNotCovered}
                onCheckedChange={(checked) => setShowNotCovered(checked === true)}
              />
              <Label htmlFor="matrix-show-not-covered" className="text-sm font-normal">
                Show not covered
              </Label>
            </div>
          )}
        </div>
        <p className="text-xs text-muted-foreground" data-testid="compliance-matrix-coverage">
          {frameworkCoverageLine(framework)}
        </p>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[40%]">Requirement</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Countermeasures</TableHead>
              <TableHead>Threats</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((group) => [
              group.name ? (
                <TableRow key={`group-${group.name}`} className="bg-muted/40 hover:bg-muted/40">
                  <TableCell colSpan={4} className="py-1.5 text-xs font-semibold">
                    {group.name}
                  </TableCell>
                </TableRow>
              ) : null,
              ...group.rows.map((row) => (
                <TableRow key={`${group.name}-${row.sectionCode}`} data-matrix-requirement={row.sectionCode}>
                  <TableCell className="w-[40%] min-w-[220px] whitespace-normal align-top text-sm">
                    <div className="font-mono text-xs font-medium">{row.sectionCode}</div>
                    {row.name && <div className="font-medium">{row.name}</div>}
                    {row.description && (
                      <div className="line-clamp-2 text-xs text-muted-foreground" title={row.description}>
                        {row.description}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="align-top">
                    <StateBadge state={row.state} />
                    {row.overdue && <div className="mt-1 text-xs text-red-700">Overdue</div>}
                  </TableCell>
                  <TableCell className="whitespace-normal align-top text-sm">
                    {row.controls.length === 0 ? (
                      <span className="text-xs text-muted-foreground">None</span>
                    ) : (
                      <ul className="space-y-0.5">
                        {row.controls.map((control) => (
                          <li key={control.id} className="flex flex-wrap items-center gap-x-1.5">
                            {/* The link opens the control beside a threat it mitigates; one linked to no threat has nowhere to open. */}
                            {control.threats.length > 0 ? (
                              <Link
                                to={`/threat-models/${threatModelId}/threat-analysis/components?countermeasure=${control.displayNumber}`}
                                className="font-mono text-xs text-blue-600 hover:underline"
                              >
                                {control.displayNumber}
                              </Link>
                            ) : (
                              <span className="font-mono text-xs" title="Not linked to any threat">
                                {control.displayNumber}
                              </span>
                            )}
                            <span>{control.name}</span>
                            <span className="text-xs text-muted-foreground">
                              {statusLabel(control.status)}
                              {control.sufficiency === 'partial' && ', partial'}
                            </span>
                            {(control.daysOverdue ?? 0) > 0 && (
                              <span className="text-xs text-red-700">{control.daysOverdue} days overdue</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-normal align-top font-mono text-xs">
                    {rowThreatNumbers(row).join(', ') || (
                      <span className="font-sans text-muted-foreground">None</span>
                    )}
                  </TableCell>
                </TableRow>
              )),
            ])}
          </TableBody>
        </Table>
      </div>
    </ReportSection>
  )
}
