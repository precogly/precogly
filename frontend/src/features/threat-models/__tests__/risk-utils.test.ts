import { describe, expect, it } from 'vitest'
import { ApiError } from '@/lib/api'
import type { RiskStatus } from '@/types/risk'
import {
  RISK_BOARD_COLUMNS,
  apiErrorMessage,
  formatTargetDate,
  groupRisksByStatus,
  threatPickerLabel,
  threatPickerMatches,
} from '../components/workspace/risk/risk-utils'

describe('groupRisksByStatus', () => {
  it('has one column per lifecycle status, in order, even when empty', () => {
    const grouped = groupRisksByStatus([])
    expect(Object.keys(grouped)).toEqual(RISK_BOARD_COLUMNS.map((column) => column.status))
    expect(Object.keys(grouped)).toEqual([
      'identified',
      'assessed',
      'mitigated',
      'accepted',
      'transferred',
      'retired',
    ])
    for (const column of Object.values(grouped)) expect(column).toEqual([])
  })

  it('puts each risk in its status column and keeps page order', () => {
    const risks = [
      { id: 1, status: 'assessed' as RiskStatus },
      { id: 2, status: 'identified' as RiskStatus },
      { id: 3, status: 'assessed' as RiskStatus },
      { id: 4, status: 'retired' as RiskStatus },
    ]
    const grouped = groupRisksByStatus(risks)
    expect(grouped.assessed.map((risk) => risk.id)).toEqual([1, 3])
    expect(grouped.identified.map((risk) => risk.id)).toEqual([2])
    expect(grouped.retired.map((risk) => risk.id)).toEqual([4])
    expect(grouped.mitigated).toEqual([])
  })

  it('drops a risk with a status that is not a column', () => {
    const grouped = groupRisksByStatus([{ id: 9, status: 'bogus' as RiskStatus }])
    expect(Object.values(grouped).flat()).toEqual([])
  })
})

describe('threatPickerLabel', () => {
  it('shows the number, the name and the targets', () => {
    expect(
      threatPickerLabel({
        threatId: 7,
        displayNumber: 'T7',
        threatName: 'API Gateway Input Injection',
        wholeSystem: false,
        targets: [{ name: 'API Gateway' }, { name: 'Filtered request' }],
      })
    ).toBe('T7 API Gateway Input Injection (API Gateway, Filtered request)')
  })

  it('says whole system for a whole-system threat', () => {
    expect(
      threatPickerLabel({
        threatId: 2,
        displayNumber: 'T2',
        threatName: 'Insider misuse',
        wholeSystem: true,
        targets: [],
      })
    ).toBe('T2 Insider misuse (whole system)')
  })

  it('skips unnamed targets and the brackets when none is named', () => {
    expect(
      threatPickerLabel({
        threatId: 3,
        displayNumber: 'T3',
        threatName: 'Tampering',
        wholeSystem: false,
        targets: [{ name: null }, { name: '  ' }],
      })
    ).toBe('T3 Tampering')
  })

  it('falls back to the number when the threat has no name', () => {
    expect(
      threatPickerLabel({
        threatId: 4,
        displayNumber: 'T4',
        threatName: null,
        wholeSystem: false,
        targets: [{ name: 'Lambda' }],
      })
    ).toBe('T4 Threat T4 (Lambda)')
  })
})

describe('threatPickerMatches', () => {
  const entry = {
    threatId: 7,
    displayNumber: 'T7',
    threatName: 'API Gateway Input Injection',
    wholeSystem: false,
    targets: [{ name: 'Filtered request' }],
  }

  it('matches the number, the name and a target, ignoring case', () => {
    expect(threatPickerMatches(entry, 't7')).toBe(true)
    expect(threatPickerMatches(entry, 'input inj')).toBe(true)
    expect(threatPickerMatches(entry, 'filtered')).toBe(true)
    expect(threatPickerMatches(entry, 'lambda')).toBe(false)
  })

  it('matches everything on an empty filter', () => {
    expect(threatPickerMatches(entry, '')).toBe(true)
    expect(threatPickerMatches(entry, '   ')).toBe(true)
  })
})

describe('apiErrorMessage', () => {
  it('joins DRF field errors with their field names', () => {
    const error = new ApiError('API Error: 400 Bad Request', 400, {
      name: ['This field may not be blank.'],
      ratingInputs: ['Give a level.'],
    })
    expect(apiErrorMessage(error, 'fallback')).toBe(
      'name: This field may not be blank. ratingInputs: Give a level.'
    )
  })

  it('passes a detail message through without a field name', () => {
    const error = new ApiError('API Error: 400 Bad Request', 400, { detail: 'No such risk.' })
    expect(apiErrorMessage(error, 'fallback')).toBe('No such risk.')
  })

  it('surfaces the methodology guard message', () => {
    const error = new ApiError('API Error: 400 Bad Request', 400, {
      riskScoringMethod: ['Delete or re-rate existing risks before changing the methodology.'],
    })
    expect(apiErrorMessage(error, 'fallback')).toContain('Delete or re-rate existing risks')
  })

  it('falls back for anything that is not an API error with a body', () => {
    expect(apiErrorMessage(new Error('boom'), 'fallback')).toBe('fallback')
    expect(apiErrorMessage(new ApiError('API Error: 500', 500, 'Server error'), 'fallback')).toBe('fallback')
    expect(apiErrorMessage(new ApiError('API Error: 400', 400, {}), 'fallback')).toBe('fallback')
  })
})

describe('formatTargetDate', () => {
  it('shows a dash for no date', () => {
    expect(formatTargetDate(null)).toBe('-')
    expect(formatTargetDate(undefined)).toBe('-')
    expect(formatTargetDate('')).toBe('-')
  })

  it('formats an ISO date without shifting the day', () => {
    const formatted = formatTargetDate('2026-09-01')
    expect(formatted).toContain('2026')
    expect(formatted).toMatch(/\b1\b/)
    expect(formatted).toMatch(/Sep/)
  })

  it('returns anything that is not an ISO date unchanged', () => {
    expect(formatTargetDate('next quarter')).toBe('next quarter')
  })
})
