import { describe, it, expect } from 'vitest'
import {
  COUNTERMEASURE_CSV_HEADERS,
  THREAT_CSV_HEADERS,
  buildCountermeasureCsvRows,
  buildThreatCsvRows,
} from '../utils/csvExport'
import { makeReportData } from './fixtures'

function column(headers: string[], row: string[], name: string): string {
  const index = headers.indexOf(name)
  expect(index, `column ${name}`).toBeGreaterThanOrEqual(0)
  return row[index]
}

describe('threat CSV rows', () => {
  const rows = buildThreatCsvRows(makeReportData())

  it('has one row per scenario, each with its number', () => {
    expect(rows).toHaveLength(2)
    expect(rows.map((row) => column(THREAT_CSV_HEADERS, row, 'Number'))).toEqual(['T7', 'T9'])
  })

  it('lists every target of a multi-target scenario and says "Whole system" for a whole-system one', () => {
    expect(column(THREAT_CSV_HEADERS, rows[0], 'Targets')).toBe('PLC; Control signals')
    expect(column(THREAT_CSV_HEADERS, rows[1], 'Targets')).toBe('Whole system')
  })

  it('carries level and score as separate columns, and no residual severity column', () => {
    expect(column(THREAT_CSV_HEADERS, rows[0], 'Level')).toBe('high')
    expect(column(THREAT_CSV_HEADERS, rows[0], 'Score')).toBe('16')
    expect(THREAT_CSV_HEADERS.some((header) => /residual|inherited/i.test(header))).toBe(false)
  })

  it('cites the controls by number', () => {
    expect(column(THREAT_CSV_HEADERS, rows[0], 'Controls')).toBe('C3')
    expect(column(THREAT_CSV_HEADERS, rows[1], 'Controls')).toBe('C9')
  })

  it('has as many cells as headers in every row', () => {
    for (const row of rows) expect(row).toHaveLength(THREAT_CSV_HEADERS.length)
  })
})

describe('countermeasure CSV rows', () => {
  const rows = buildCountermeasureCsvRows(makeReportData())

  it('has a row per linked control and one per unattached control, all numbered', () => {
    expect(rows.map((row) => column(COUNTERMEASURE_CSV_HEADERS, row, 'Number'))).toEqual(['C3', 'C9', 'C14'])
  })

  it('shows the threat number and its targets next to a linked control', () => {
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[0], 'Threat number')).toBe('T7')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[0], 'Threat targets')).toBe('PLC; Control signals')
  })

  it('shows scope, provider and source', () => {
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[0], 'Applies to')).toBe('Whole system')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[1], 'Applies to')).toBe('PLC')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[1], 'Implemented by')).toBe('Plant IT')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[1], 'Source')).toBe('ISA 62443 audit')
  })

  it('leaves the threat columns empty for a control not linked to any threat', () => {
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[2], 'Threat number')).toBe('')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[2], 'Threat')).toBe('')
    expect(column(COUNTERMEASURE_CSV_HEADERS, rows[2], 'Applies to')).toBe('PLC')
    expect(COUNTERMEASURE_CSV_HEADERS.some((header) => /inherited/i.test(header))).toBe(false)
  })

  it('has as many cells as headers in every row', () => {
    for (const row of rows) expect(row).toHaveLength(COUNTERMEASURE_CSV_HEADERS.length)
  })
})
