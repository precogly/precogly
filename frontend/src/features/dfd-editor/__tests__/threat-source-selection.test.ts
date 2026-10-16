import { describe, it, expect } from 'vitest'
import {
  threatSourceIdsFromThreat,
  toggleThreatSourceId,
} from '../components/threat-analysis/threat-source-selection'

describe('threatSourceIdsFromThreat', () => {
  it('lists the ids of the threat sources it has', () => {
    const threatSources = [
      { id: 2, name: 'External' },
      { id: 4, name: 'Insider' },
    ]
    expect(threatSourceIdsFromThreat(threatSources)).toEqual([2, 4])
  })

  it('gives an empty list when the threat has none or the field is missing', () => {
    expect(threatSourceIdsFromThreat([])).toEqual([])
    expect(threatSourceIdsFromThreat(undefined)).toEqual([])
  })
})

describe('toggleThreatSourceId', () => {
  it('adds a source that is switched on', () => {
    expect(toggleThreatSourceId([2], 4, true)).toEqual([2, 4])
  })

  it('does not add a source twice', () => {
    expect(toggleThreatSourceId([2, 4], 4, true)).toEqual([2, 4])
  })

  it('removes a source that is switched off, down to the empty list', () => {
    expect(toggleThreatSourceId([2, 4], 2, false)).toEqual([4])
    expect(toggleThreatSourceId([4], 4, false)).toEqual([])
  })

  it('leaves the input list unchanged', () => {
    const selectedIds = [2]
    toggleThreatSourceId(selectedIds, 4, true)
    expect(selectedIds).toEqual([2])
  })
})
