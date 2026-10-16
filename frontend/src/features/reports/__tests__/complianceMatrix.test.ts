import { describe, it, expect } from 'vitest'
import type { ComplianceMatrixFramework, ReportData } from '../types/report'
import {
  frameworkCoverageLine,
  rowThreatNumbers,
  stateCount,
  visibleMatrixGroups,
} from '../utils/complianceMatrix'
import { COMPLIANCE_MATRIX_CSV_HEADERS, buildComplianceMatrixCsvRows } from '../utils/csvExport'

const control = (displayNumber: string, threats: string[], extra: Partial<{ sufficiency: 'full' | 'partial'; daysOverdue: number | null }> = {}) => ({
  id: Number(displayNumber.slice(1)),
  displayNumber,
  name: `Control ${displayNumber}`,
  status: 'planned',
  sufficiency: extra.sufficiency ?? ('full' as const),
  daysOverdue: extra.daysOverdue ?? null,
  threats,
})

const installed: ComplianceMatrixFramework = {
  name: 'Example Standard',
  version: '1.0',
  installed: true,
  packRequirementCount: 3,
  mappedRequirementCount: 2,
  stateCounts: [
    { state: 'satisfied', count: 0 },
    { state: 'covered', count: 1 },
    { state: 'partial_only', count: 1 },
    { state: 'not_covered', count: 1 },
  ],
  groups: [
    {
      name: 'AC',
      rows: [
        {
          requirementId: 1,
          sectionCode: 'AC-1',
          name: 'Policy',
          description: 'Have a policy',
          state: 'covered',
          controls: [control('C2', ['T10', 'T2']), control('C5', ['T2'], { daysOverdue: 4 })],
          overdue: true,
        },
        {
          requirementId: 2,
          sectionCode: 'AC-2',
          name: '',
          description: 'Accounts',
          state: 'partial_only',
          controls: [control('C7', [], { sufficiency: 'partial' })],
          overdue: false,
        },
        { requirementId: 3, sectionCode: 'AC-3', name: '', description: 'Enforcement', state: 'not_covered', controls: [], overdue: false },
      ],
    },
  ],
}

const notInstalled: ComplianceMatrixFramework = {
  ...installed,
  name: 'ISO 27001',
  version: '',
  installed: false,
  packRequirementCount: null,
  mappedRequirementCount: 1,
}

describe('compliance matrix helpers', () => {
  it('states coverage against the pack, never the whole standard', () => {
    expect(frameworkCoverageLine(installed)).toBe(
      '2 of the 3 requirements in this pack have a countermeasure. The pack may hold only part of the standard.'
    )
    expect(frameworkCoverageLine(notInstalled)).toContain('Framework not installed')
  })

  it('hides not covered rows on request and drops empty groups', () => {
    expect(visibleMatrixGroups(installed, true)[0].rows).toHaveLength(3)
    expect(visibleMatrixGroups(installed, false)[0].rows.map((row) => row.sectionCode)).toEqual(['AC-1', 'AC-2'])
  })

  it('reads a state count and lists threats once, in number order', () => {
    expect(stateCount(installed, 'not_covered')).toBe(1)
    expect(rowThreatNumbers(installed.groups[0].rows[0])).toEqual(['T2', 'T10'])
  })
})

describe('compliance matrix CSV', () => {
  it('writes one line per requirement and countermeasure, and one per uncovered requirement', () => {
    const rows = buildComplianceMatrixCsvRows({ complianceMatrix: [installed] } as unknown as ReportData)
    expect(rows).toHaveLength(4)
    expect(rows.every((row) => row.length === COMPLIANCE_MATRIX_CSV_HEADERS.length)).toBe(true)
    expect(rows[0].slice(0, 7)).toEqual(['Example Standard 1.0', 'yes', 'AC', 'AC-1', 'Policy: Have a policy', 'Covered', 'C2'])
    expect(rows[1][10]).toBe('4')
    expect(rows[3].slice(3, 7)).toEqual(['AC-3', 'Enforcement', 'Not covered', ''])
  })

  it('writes nothing without a matrix', () => {
    expect(buildComplianceMatrixCsvRows({} as ReportData)).toEqual([])
  })
})
