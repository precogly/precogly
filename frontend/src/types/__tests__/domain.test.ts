import { describe, it, expect } from 'vitest'
import { formatTaxonomyEntryLabel, getTaxonomyEntryBgClass } from '../domain'

describe('formatTaxonomyEntryLabel', () => {
  it('shows a CAPEC id once, as the pack stores it', () => {
    expect(formatTaxonomyEntryLabel({ taxonomySlug: 'capec', externalId: 'CAPEC-94', title: 'Adversary in the Middle (AiTM)' })).toBe(
      'CAPEC-94'
    )
  })

  it('adds the CAPEC prefix to a bare id from older data', () => {
    expect(formatTaxonomyEntryLabel({ taxonomySlug: 'capec', externalId: '94', title: 'Adversary in the Middle (AiTM)' })).toBe(
      'CAPEC-94'
    )
  })

  it('keeps CWE and ATT&CK ids as they are', () => {
    expect(formatTaxonomyEntryLabel({ taxonomySlug: 'cwe', externalId: 'CWE-494', title: 'Download of Code' })).toBe('CWE-494')
    expect(formatTaxonomyEntryLabel({ taxonomySlug: 'mitre-attack', externalId: 'T1190', title: 'Exploit' })).toBe('T1190')
  })
})

describe('getTaxonomyEntryBgClass', () => {
  it('gives ATT&CK for ICS its own colour, not the fallback', () => {
    expect(getTaxonomyEntryBgClass({ taxonomySlug: 'mitre-attack-ics', externalId: 'T1693.002', title: 'Modify Firmware' })).toContain(
      'bg-rose-50'
    )
  })
})
