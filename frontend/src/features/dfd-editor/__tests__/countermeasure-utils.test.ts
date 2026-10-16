import { describe, it, expect } from 'vitest'
import {
  countermeasureStatusAction,
  countermeasureStatusOptions,
  isCountermeasureOverdue,
  overdueCountermeasures,
  todayIsoDate,
  formatAlsoMitigatesLine,
  formatTargetList,
  effectivenessFromInput,
  effectivenessToInput,
  sameTargets,
} from '../components/threat-analysis/countermeasure-utils'

const named = (name: string | null) => ({ type: 'component' as const, id: 1, name, blueprintId: 1 })

describe('formatAlsoMitigatesLine', () => {
  it('spells out up to two targets', () => {
    expect(
      formatAlsoMitigatesLine({
        threatId: 21,
        displayNumber: 'T21',
        threatName: 'Firmware tampering',
        targets: [named('PLC'), named('Engineering workstation')],
      })
    ).toBe('T21 Firmware tampering (PLC, Engineering workstation)')
  })

  it('folds the rest into "and N more"', () => {
    expect(
      formatAlsoMitigatesLine({
        threatId: 12,
        displayNumber: 'T12',
        threatName: 'API Gateway Input Injection',
        targets: [
          named('API Gateway'),
          named('Filtered request'),
          named('A'),
          named('B'),
          named('C'),
          named('D'),
          named('E'),
        ],
      })
    ).toBe('T12 API Gateway Input Injection (API Gateway, Filtered request, and 5 more)')
  })

  it('says whole system for a threat with no targets', () => {
    expect(
      formatAlsoMitigatesLine({ threatId: 1, displayNumber: 'T1', threatName: 'No incident response plan', targets: [] })
    ).toBe('T1 No incident response plan (whole system)')
  })

  it('falls back on a nameless threat and a nameless target', () => {
    expect(formatAlsoMitigatesLine({ threatId: 2, displayNumber: 'T2', threatName: null, targets: [named(null)] })).toBe(
      'T2 Unnamed threat (Unnamed)'
    )
  })
})

describe('formatTargetList', () => {
  it('takes a custom cut-off', () => {
    expect(formatTargetList([named('A'), named('B'), named('C')], 3)).toBe('A, B, C')
    expect(formatTargetList([named('A'), named('B'), named('C')], 1)).toBe('A, and 2 more')
  })
})

describe('sameTargets', () => {
  it('ignores order and spots a change', () => {
    const left = [
      { type: 'component' as const, id: 1 },
      { type: 'flow' as const, id: 2 },
    ]
    expect(sameTargets(left, [...left].reverse())).toBe(true)
    expect(sameTargets(left, [{ type: 'component', id: 1 }])).toBe(false)
    expect(sameTargets(left, [{ type: 'component', id: 1 }, { type: 'zone', id: 2 }])).toBe(false)
  })
})

describe('effectiveness input', () => {
  it('round-trips the not-assessed state as an empty string', () => {
    expect(effectivenessToInput(null)).toBe('')
    expect(effectivenessFromInput('')).toBeNull()
    expect(effectivenessFromInput('   ')).toBeNull()
  })

  it('keeps whole percentages and refuses the rest', () => {
    expect(effectivenessToInput(80)).toBe('80')
    expect(effectivenessFromInput('80')).toBe(80)
    expect(effectivenessFromInput('79.6')).toBe(80)
    expect(effectivenessFromInput('101')).toBeUndefined()
    expect(effectivenessFromInput('-1')).toBeUndefined()
    expect(effectivenessFromInput('abc')).toBeUndefined()
  })
})

describe('isCountermeasureOverdue', () => {
  const today = '2026-10-13'

  it('flags a control whose due date has passed and that is not in effect', () => {
    expect(isCountermeasureOverdue({ status: 'gap', dueDate: '2026-10-12' }, today)).toBe(true)
    expect(isCountermeasureOverdue({ status: 'planned', dueDate: '2026-01-01' }, today)).toBe(true)
  })

  it('never flags a control in effect, due today or later, or without a date', () => {
    expect(isCountermeasureOverdue({ status: 'verified', dueDate: '2026-01-01' }, today)).toBe(false)
    expect(isCountermeasureOverdue({ status: 'platform', dueDate: '2026-01-01' }, today)).toBe(false)
    expect(isCountermeasureOverdue({ status: 'implemented', dueDate: '2026-01-01' }, today)).toBe(false)
    expect(isCountermeasureOverdue({ status: 'gap', dueDate: today }, today)).toBe(false)
    expect(isCountermeasureOverdue({ status: 'gap', dueDate: '2026-12-01' }, today)).toBe(false)
    expect(isCountermeasureOverdue({ status: 'gap', dueDate: null }, today)).toBe(false)
  })

  it('formats today in local time as YYYY-MM-DD', () => {
    expect(todayIsoDate(new Date(2026, 0, 5))).toBe('2026-01-05')
  })
})

describe('overdueCountermeasures', () => {
  it('keeps only overdue ones, most overdue first, then by number', () => {
    const rows = [
      { number: 1, daysOverdue: null },
      { number: 2, daysOverdue: 3 },
      { number: 3, daysOverdue: 40 },
      { number: 4, daysOverdue: 3 },
      { number: 5, daysOverdue: 0 },
    ]
    expect(overdueCountermeasures(rows).map((row) => row.number)).toEqual([3, 2, 4])
  })
})

describe('countermeasureStatusOptions', () => {
  it('offers the four statuses anyone can set', () => {
    expect(countermeasureStatusOptions({})).toEqual(['gap', 'planned', 'verified', 'waived'])
  })

  it('adds platform first for the Security Team', () => {
    expect(countermeasureStatusOptions({ isSecurityTeam: true })).toEqual(['platform', 'gap', 'planned', 'verified', 'waived'])
  })

  it('keeps a current status that is not pickable, so a select is never blank', () => {
    expect(countermeasureStatusOptions({ current: 'in_progress' })).toEqual(['in_progress', 'gap', 'planned', 'verified', 'waived'])
    expect(countermeasureStatusOptions({ current: 'platform' })).toEqual(['platform', 'gap', 'planned', 'verified', 'waived'])
  })

  it('does not repeat a current status that is already listed', () => {
    expect(countermeasureStatusOptions({ current: 'waived' })).toEqual(['gap', 'planned', 'verified', 'waived'])
    expect(countermeasureStatusOptions({ current: 'platform', isSecurityTeam: true })).toEqual(['platform', 'gap', 'planned', 'verified', 'waived'])
  })
})

describe('countermeasureStatusAction', () => {
  it('asks for an owner before Planned when there is none', () => {
    expect(countermeasureStatusAction('planned', false)).toBe('assign-owner')
    expect(countermeasureStatusAction('planned', true)).toBe('change')
  })

  it('always asks for a reason before Waived', () => {
    expect(countermeasureStatusAction('waived', false)).toBe('waive')
    expect(countermeasureStatusAction('waived', true)).toBe('waive')
  })

  it('saves every other status as is', () => {
    expect(countermeasureStatusAction('gap', false)).toBe('change')
    expect(countermeasureStatusAction('verified', false)).toBe('change')
    expect(countermeasureStatusAction('platform', false)).toBe('change')
  })
})
