import { describe, it, expect } from 'vitest'
import {
  normalizeAuthenticationSelection,
  normalizeExclusiveSelection,
} from '../lib/authentication-selection'

describe('authentication and authorization pickers (plan I5, I9)', () => {
  describe('normalizeExclusiveSelection', () => {
    it('picking none clears everything else', () => {
      expect(normalizeExclusiveSelection(['oauth2', 'jwt'], ['oauth2', 'jwt', 'none'])).toEqual(['none'])
    })

    it('picking a method drops none', () => {
      expect(normalizeExclusiveSelection(['none'], ['none', 'rbac'])).toEqual(['rbac'])
    })

    it('removing a value keeps the rest as they are', () => {
      expect(normalizeExclusiveSelection(['oauth2', 'jwt'], ['jwt'])).toEqual(['jwt'])
      expect(normalizeExclusiveSelection(['none'], [])).toEqual([])
    })

    it('keeps a custom name and drops blanks and duplicates', () => {
      expect(normalizeExclusiveSelection([], ['custom-sso', '', 'custom-sso'])).toEqual(['custom-sso'])
    })
  })

  describe('normalizeAuthenticationSelection', () => {
    it('applies the none rule', () => {
      expect(normalizeAuthenticationSelection(['mtls'], ['mtls', 'none'])).toEqual(['none'])
    })

    it('a real method replaces the "method not specified" placeholder', () => {
      expect(normalizeAuthenticationSelection(['unspecified'], ['unspecified', 'mtls'])).toEqual(['mtls'])
    })

    it('the placeholder can be chosen on its own', () => {
      expect(normalizeAuthenticationSelection([], ['unspecified'])).toEqual(['unspecified'])
    })

    it('removing a method leaves the placeholder alone when it was already there', () => {
      expect(normalizeAuthenticationSelection(['unspecified', 'x'], ['unspecified'])).toEqual(['unspecified'])
    })
  })
})
