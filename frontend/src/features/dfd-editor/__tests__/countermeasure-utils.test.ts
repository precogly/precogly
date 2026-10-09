import { describe, it, expect } from 'vitest'
import {
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
