/**
 * CSV exports of the report payload (plan 11.6). Each export is a header list
 * and a pure row builder, so the columns can be tested without a browser.
 * Threats and controls carry their number (`T7`, `C3`) and targets so a
 * spreadsheet outside Precogly can cite them (#590).
 */

import type { ReportData, ReportRating, ReportThreat } from '../types/report'
import { formatTaxonomyEntryLabel } from '@/types/domain'
import {
  assumptionTopicLabel,
  assumptionValidityLabel,
  countermeasureStatusLabel,
  methodologyNameLabel,
  riskDomainLabel,
  riskExposureLabel,
  riskStatusLabel,
  targetsText,
  threatStatusLabel,
} from './labels'

function downloadCsv(filename: string, headers: string[], rows: string[][]): void {
  const csvContent = [
    headers.join(','),
    ...rows.map((row) => row.map((cell) => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(',')),
  ].join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function slugify(name: string): string {
  return name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '')
}

function ratingLevel(rating: ReportRating | null): string {
  return rating?.level ?? ''
}

function ratingScore(rating: ReportRating | null): string {
  return rating?.score == null ? '' : String(rating.score)
}

function threatTargets(threat: ReportThreat): string {
  return threat.wholeSystem ? 'Whole system' : threat.targets.join('; ')
}

// ---------------------------------------------------------------------------
// Threats
// ---------------------------------------------------------------------------

export const THREAT_CSV_HEADERS = [
  'Number',
  'Threat',
  'Description',
  'Targets',
  'Classifications',
  'Level',
  'Score',
  'Rating method',
  'Status',
  'Business objectives',
  'Controls',
]

/** One row per active scenario, in payload order. */
export function buildThreatCsvRows(data: ReportData): string[][] {
  return data.threatAnalysis.threats.map((threat) => [
    threat.displayNumber,
    threat.threatName,
    threat.threatDescription,
    threatTargets(threat),
    (threat.taxonomyEntries ?? []).map((entry) => formatTaxonomyEntryLabel(entry)).join('; '),
    ratingLevel(threat.rating),
    ratingScore(threat.rating),
    threat.rating ? methodologyNameLabel(threat.rating.methodology) || threat.rating.methodology : '',
    threatStatusLabel(threat.status),
    threat.businessObjectives.join('; '),
    threat.countermeasures.map((countermeasure) => countermeasure.displayNumber).join('; '),
  ])
}

export function exportThreatsCSV(data: ReportData, modelName: string): void {
  downloadCsv(`${slugify(modelName)}-threats.csv`, THREAT_CSV_HEADERS, buildThreatCsvRows(data))
}

// ---------------------------------------------------------------------------
// Countermeasures
// ---------------------------------------------------------------------------

export const COUNTERMEASURE_CSV_HEADERS = [
  'Number',
  'Countermeasure',
  'Control type',
  'Status',
  'Priority',
  'Applies to',
  'Implemented by',
  'Source',
  'Compliance standards',
  'Assigned owner',
  'Threat number',
  'Threat',
  'Threat targets',
]

/**
 * One row per control and linked threat, then one row per control with no
 * threat link (I3) with the threat columns empty.
 */
export function buildCountermeasureCsvRows(data: ReportData): string[][] {
  const rows: string[][] = []
  for (const threat of data.threatAnalysis.threats) {
    for (const countermeasure of threat.countermeasures) {
      rows.push([
        countermeasure.displayNumber,
        countermeasure.countermeasureName,
        (countermeasure.controlFunctions ?? []).join(', '),
        countermeasureStatusLabel(countermeasure.status),
        countermeasure.priority,
        targetsText(countermeasure.scope),
        countermeasure.implementedByParty ?? '',
        countermeasure.source ?? '',
        (countermeasure.complianceStandards ?? [])
          .map((standard) => `${standard.frameworkName} ${standard.sectionCode}`)
          .join('; '),
        countermeasure.assignedOwnerEmail ?? '',
        threat.displayNumber,
        threat.threatName,
        threatTargets(threat),
      ])
    }
  }
  for (const control of data.countermeasureSummary.unattached) {
    rows.push([
      control.controlNumber,
      control.countermeasureName,
      '',
      countermeasureStatusLabel(control.status),
      '',
      targetsText(control.scope),
      '',
      '',
      '',
      '',
      '',
      '',
      '',
    ])
  }
  return rows
}

export function exportCountermeasuresCSV(data: ReportData, modelName: string): void {
  downloadCsv(`${slugify(modelName)}-countermeasures.csv`, COUNTERMEASURE_CSV_HEADERS, buildCountermeasureCsvRows(data))
}

// ---------------------------------------------------------------------------
// Risks
// ---------------------------------------------------------------------------

export const RISK_CSV_HEADERS = [
  'Risk',
  'Status',
  'Statement',
  'Description',
  'Exposure',
  'Domains',
  'Inherent level',
  'Inherent score',
  'Residual level',
  'Residual score',
  'Target level',
  'Target score',
  'Owner',
  'Contributing threats',
  'Responses',
  'Business objectives',
]

export function buildRiskCsvRows(data: ReportData): string[][] {
  return data.risks.map((risk) => [
    risk.name,
    riskStatusLabel(risk.status),
    risk.statement,
    risk.description,
    riskExposureLabel(risk.exposure),
    risk.domains.map(riskDomainLabel).join('; '),
    ratingLevel(risk.inherent),
    ratingScore(risk.inherent),
    ratingLevel(risk.residual),
    ratingScore(risk.residual),
    ratingLevel(risk.target),
    ratingScore(risk.target),
    risk.ownerEmail ?? '',
    risk.contributingThreats.map((threat) => threat.displayNumber).join('; '),
    String(risk.responses.length),
    risk.businessObjectives.join('; '),
  ])
}

export function exportRisksCSV(data: ReportData, modelName: string): void {
  downloadCsv(`${slugify(modelName)}-risks.csv`, RISK_CSV_HEADERS, buildRiskCsvRows(data))
}

// ---------------------------------------------------------------------------
// Assumptions
// ---------------------------------------------------------------------------

export const ASSUMPTION_CSV_HEADERS = [
  'Assumption',
  'Validity',
  'Topic',
  'Impact',
  'Owner',
  'Validation method',
  'Validation date',
  'Components',
  'Blueprint',
]

export function buildAssumptionCsvRows(data: ReportData): string[][] {
  return data.scope.assumptions.map((assumption) => [
    assumption.description,
    assumptionValidityLabel(assumption.validity),
    assumptionTopicLabel(assumption.topic),
    assumption.impact,
    assumption.owner,
    assumption.validationMethod,
    assumption.validationDate ?? '',
    assumption.components.join('; '),
    assumption.blueprint,
  ])
}

export function exportAssumptionsCSV(data: ReportData, modelName: string): void {
  downloadCsv(`${slugify(modelName)}-assumptions.csv`, ASSUMPTION_CSV_HEADERS, buildAssumptionCsvRows(data))
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export const COMPLIANCE_CSV_HEADERS = ['Framework', 'Total requirements', 'Covered', 'Coverage %', 'Satisfied', 'Satisfaction %']

export function buildComplianceCsvRows(data: ReportData): string[][] {
  return data.compliance.frameworks.map((framework) => [
    framework.name,
    String(framework.totalRequirements),
    String(framework.coveredRequirements),
    `${framework.coveragePercentage.toFixed(1)}%`,
    String(framework.satisfiedRequirements),
    `${framework.satisfactionPercentage.toFixed(1)}%`,
  ])
}

export function exportComplianceCSV(data: ReportData, modelName: string): void {
  downloadCsv(`${slugify(modelName)}-compliance.csv`, COMPLIANCE_CSV_HEADERS, buildComplianceCsvRows(data))
}
