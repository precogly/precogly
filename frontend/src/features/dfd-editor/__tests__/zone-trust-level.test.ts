import { describe, it, expect } from 'vitest'
import {
  NEW_ZONE_TRUST_LEVEL,
  getDisplayedTrustLevel,
  getTrustLevel,
  zoneTypeHasTrustLevel,
} from '../lib/zone-trust-level'

describe('zone trust level display rule (plan F13, 11.11)', () => {
  it('a new zone starts at 50', () => {
    expect(NEW_ZONE_TRUST_LEVEL).toBe(50)
  })

  describe('getTrustLevel', () => {
    it('is null when the key is missing: no 75 fallback', () => {
      expect(getTrustLevel({ label: 'DMZ' })).toBeNull()
      expect(getTrustLevel(undefined)).toBeNull()
      expect(getTrustLevel(null)).toBeNull()
    })

    it('is null for a value that is not a number', () => {
      expect(getTrustLevel({ trustLevel: '50' })).toBeNull()
      expect(getTrustLevel({ trustLevel: Number.NaN })).toBeNull()
    })

    it('returns the number, clamped to 0..100', () => {
      expect(getTrustLevel({ trustLevel: 0 })).toBe(0)
      expect(getTrustLevel({ trustLevel: 60 })).toBe(60)
      expect(getTrustLevel({ trustLevel: 140 })).toBe(100)
      expect(getTrustLevel({ trustLevel: -5 })).toBe(0)
    })
  })

  describe('zoneTypeHasTrustLevel', () => {
    it('is true for trust and network zones only', () => {
      expect(zoneTypeHasTrustLevel('trust')).toBe(true)
      expect(zoneTypeHasTrustLevel('network')).toBe(true)
      expect(zoneTypeHasTrustLevel('physical')).toBe(false)
      expect(zoneTypeHasTrustLevel('geographic')).toBe(false)
    })
  })

  describe('getDisplayedTrustLevel', () => {
    it('shows the level of a trust zone (the default type) when set', () => {
      expect(getDisplayedTrustLevel({ trustLevel: 60 })).toBe(60)
      expect(getDisplayedTrustLevel({ zoneType: 'trust', trustLevel: 0 })).toBe(0)
    })

    it('shows the level of a network zone', () => {
      expect(getDisplayedTrustLevel({ zoneType: 'network', trustLevel: 90 })).toBe(90)
    })

    it('shows nothing when the level is not set', () => {
      expect(getDisplayedTrustLevel({ zoneType: 'trust' })).toBeNull()
      expect(getDisplayedTrustLevel({ zoneType: 'network', trustLevel: null })).toBeNull()
    })

    it('shows nothing on a zone type that carries no trust level, even with a stale value', () => {
      expect(getDisplayedTrustLevel({ zoneType: 'physical', trustLevel: 40 })).toBeNull()
    })
  })
})
