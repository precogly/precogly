import { describe, it, expect } from 'vitest'
import {
  threatUiId,
  threatIdFromUiId,
  isThreatUiId,
  countermeasureUiId,
  countermeasureIdFromUiId,
  parseCountermeasureId,
} from '../lib/threat-ids'

describe('threat UI ids', () => {
  it('builds threat-{id}', () => {
    expect(threatUiId(7)).toBe('threat-7')
    expect(threatUiId(1203)).toBe('threat-1203')
  })

  it('reads the backend id back', () => {
    expect(threatIdFromUiId('threat-7')).toBe(7)
    expect(threatIdFromUiId(threatUiId(42))).toBe(42)
  })

  it('returns null for anything that is not a threat id', () => {
    expect(threatIdFromUiId('backend-7')).toBeNull()
    expect(threatIdFromUiId('backend-flow-7')).toBeNull()
    expect(threatIdFromUiId('threat-')).toBeNull()
    expect(threatIdFromUiId('threat-abc')).toBeNull()
    expect(threatIdFromUiId('cm-7')).toBeNull()
    expect(threatIdFromUiId('')).toBeNull()
    expect(threatIdFromUiId(undefined)).toBeNull()
    expect(threatIdFromUiId(null)).toBeNull()
  })

  it('isThreatUiId follows the parser', () => {
    expect(isThreatUiId('threat-3')).toBe(true)
    expect(isThreatUiId('shared-threat-3')).toBe(false)
  })
})

describe('countermeasure UI ids', () => {
  it('builds and reads cm-{id}', () => {
    expect(countermeasureUiId(3)).toBe('cm-3')
    expect(countermeasureIdFromUiId('cm-3')).toBe(3)
    expect(countermeasureIdFromUiId('ctcm-local-1')).toBeNull()
  })

  it('parseCountermeasureId tells backend rows from local ones', () => {
    expect(parseCountermeasureId('cm-9')).toEqual({ type: 'backend', id: 9 })
    expect(parseCountermeasureId('cm-x')).toEqual({ type: 'backend', id: null })
    expect(parseCountermeasureId('ctcm-threat-7-lib-1-123')).toEqual({ type: 'local', id: null })
  })
})
