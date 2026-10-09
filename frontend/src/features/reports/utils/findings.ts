/**
 * The findings derived from the report data, shared by the web Findings
 * section and the Word export.
 */

import type { ReportData } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'info'

export interface ReportFinding {
  severity: FindingSeverity
  title: string
  detail: string
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`
}

/** Up to `limit` numbered names, "T7 Logic tampering", with "and N more" past the limit. */
function numberedList(items: readonly { displayNumber: string; name: string }[], limit = 5): string {
  const shown = items.slice(0, limit).map((item) => `${item.displayNumber} ${item.name}`)
  const rest = items.length - shown.length
  return rest > 0 ? `${shown.join(', ')} and ${rest} more` : shown.join(', ')
}

/**
 * The findings derived from the report data, shared by the web section and
 * the Word export. Threats and controls are cited by number so a reader can
 * find them in the detail tables (#590).
 */
export function deriveFindings(data: ReportData, depth: SectionDepth): ReportFinding[] {
  const { summaryMetrics, countermeasureSummary, threatAnalysis, metadata } = data
  const findings: ReportFinding[] = []

  const exposedThreats = threatAnalysis.threats.filter((threat) => threat.status === 'exposed')
  if (exposedThreats.length > 0) {
    findings.push({
      severity: exposedThreats.length > 5 ? 'critical' : 'high',
      title: pluralize(exposedThreats.length, 'exposed threat'),
      detail: numberedList(
        exposedThreats.map((threat) => ({ displayNumber: threat.displayNumber, name: threat.threatName }))
      ),
    })
  }

  const criticalGaps = countermeasureSummary.gaps.filter((gap) => gap.priority === 'critical')
  if (criticalGaps.length > 0) {
    findings.push({
      severity: 'critical',
      title: pluralize(criticalGaps.length, 'critical-priority gap'),
      detail: numberedList(criticalGaps.map((gap) => ({ displayNumber: gap.controlNumber, name: gap.countermeasureName }))),
    })
  }

  const highRisks = data.risks.filter((risk) => {
    const level = (risk.residual ?? risk.inherent)?.level
    return level === 'critical' || level === 'high'
  })
  if (highRisks.length > 0) {
    findings.push({
      severity: 'high',
      title: pluralize(highRisks.length, 'high or critical residual risk'),
      detail: highRisks.map((risk) => risk.name).join(', '),
    })
  }

  const invalidAssumptions = data.scope.assumptions.filter((assumption) => assumption.validity === 'invalid')
  if (invalidAssumptions.length > 0) {
    findings.push({
      severity: 'high',
      title: pluralize(invalidAssumptions.length, 'invalid assumption'),
      detail: 'The model relies on an assumption that was found false. Re-check the threats it affects.',
    })
  }

  const unverifiedAssumptions = data.scope.assumptions.filter(
    (assumption) => assumption.validity === 'unverified' || assumption.validity === 'unknown'
  )
  if (unverifiedAssumptions.length > 0) {
    findings.push({
      severity: 'medium',
      title: pluralize(unverifiedAssumptions.length, 'unverified assumption'),
      detail: 'Verify or reject these before relying on the model.',
    })
  }

  if (metadata.review.approvalState === 'changed') {
    findings.push({
      severity: 'medium',
      title: 'Changed since approval',
      detail: 'The model differs from what was approved. A new approval is needed.',
    })
  } else if (metadata.review.approvalState === 'review_due') {
    findings.push({
      severity: 'medium',
      title: 'Review due',
      detail: 'The approval has passed its valid-until date.',
    })
  }

  if (depth === 'compliance') {
    const lowCoverageFrameworks = data.compliance.frameworks.filter((framework) => framework.coveragePercentage < 50)
    if (lowCoverageFrameworks.length > 0) {
      findings.push({
        severity: 'high',
        title: `${pluralize(lowCoverageFrameworks.length, 'framework')} with under 50% coverage`,
        detail: lowCoverageFrameworks.map((framework) => `${framework.name} (${framework.coveragePercentage}%)`).join(', '),
      })
    }
  }

  if (countermeasureSummary.unattached.length > 0) {
    findings.push({
      severity: 'info',
      title: `${pluralize(countermeasureSummary.unattached.length, 'control')} not linked to any threat`,
      detail: `${numberedList(
        countermeasureSummary.unattached.map((item) => ({ displayNumber: item.controlNumber, name: item.countermeasureName }))
      )}. Not counted in coverage or gap figures.`,
    })
  }

  if (summaryMetrics.totalWaived > 0) {
    findings.push({
      severity: 'info',
      title: pluralize(summaryMetrics.totalWaived, 'waived countermeasure'),
      detail: 'Risk accepted for these countermeasures.',
    })
  }

  const mitigatedCount = summaryMetrics.threatsByStatus?.mitigated || 0
  if (mitigatedCount > 0) {
    findings.push({
      severity: 'info',
      title: pluralize(mitigatedCount, 'fully mitigated threat'),
      detail: 'Threats with all countermeasures verified or at platform level.',
    })
  }

  if (depth === 'critical') {
    return findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
  }
  return findings
}
