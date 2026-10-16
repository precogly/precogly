import { describe, it, expect } from 'vitest'
import {
  NOT_SET_LABEL,
  countLabel,
  listSummary,
  systemContextSummary,
  systemDetailsSummary,
  systemSummary,
} from '../components/workspace/overview-utils'

describe('overview button summaries', () => {
  it('counts with singular and plural', () => {
    expect(countLabel(1, 'objective')).toBe('1 objective')
    expect(countLabel(3, 'objective')).toBe('3 objectives')
  })

  it('says "not set" for an empty list', () => {
    expect(listSummary(0, 'use case')).toBe(NOT_SET_LABEL)
    expect(listSummary(2, 'use case')).toBe('2 use cases')
  })

  it('calls system details described once there is a description or a primary system', () => {
    expect(systemDetailsSummary('', null)).toBe(NOT_SET_LABEL)
    expect(systemDetailsSummary('   ', undefined)).toBe(NOT_SET_LABEL)
    expect(systemDetailsSummary('An LNG plant', null)).toBe('described')
    expect(systemDetailsSummary('', 4)).toBe('described')
  })

  it('sums up the system context', () => {
    expect(systemContextSummary({ assumptions: 0, unverifiedAssumptions: 0, outOfScopeItems: 0, dataAssets: 0 })).toBe(
      NOT_SET_LABEL
    )
    expect(systemContextSummary({ assumptions: 3, unverifiedAssumptions: 1, outOfScopeItems: 2, dataAssets: 1 })).toBe(
      '3 assumptions (1 not verified), 2 out of scope, 1 data asset'
    )
    expect(systemContextSummary({ assumptions: 1, unverifiedAssumptions: 0, outOfScopeItems: 0, dataAssets: 0 })).toBe(
      '1 assumption'
    )
  })

  it('sums up the merged System button', () => {
    expect(systemSummary({ criticality: '', description: '', primarySystemId: null, contextSummary: NOT_SET_LABEL })).toBe(
      NOT_SET_LABEL
    )
    expect(
      systemSummary({ criticality: 'critical', description: 'An LNG plant', primarySystemId: null, contextSummary: NOT_SET_LABEL })
    ).toBe('Critical criticality, described')
    expect(
      systemSummary({ criticality: 'high', description: '', primarySystemId: null, contextSummary: '2 assumptions' })
    ).toBe('High criticality, 2 assumptions')
  })
})
