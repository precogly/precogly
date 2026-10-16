import { describe, it, expect } from 'vitest'
import {
  getZoneType,
  getFlowType,
  getBoundaryType,
  getComponentKind,
  getAuthentication,
  kindForNodeType,
  isKnownAuthenticationType,
} from '../lib/canvas-defaults'
import { isAuthenticated, requiresAuthorization } from '@/lib/authentication'

describe('canvas-defaults accessors', () => {
  describe('getZoneType', () => {
    it('defaults to trust when the key is missing', () => {
      expect(getZoneType({ label: 'DMZ' })).toBe('trust')
      expect(getZoneType(undefined)).toBe('trust')
      expect(getZoneType(null)).toBe('trust')
    })

    it('returns the key when it is a spec value', () => {
      expect(getZoneType({ zoneType: 'network' })).toBe('network')
      expect(getZoneType({ zoneType: 'tenant' })).toBe('tenant')
    })

    it('falls back to trust for a value outside the spec list', () => {
      expect(getZoneType({ zoneType: 'zoneRestricted' })).toBe('trust')
      expect(getZoneType({ zoneType: 42 })).toBe('trust')
    })
  })

  describe('getFlowType', () => {
    it('defaults to data when the key is missing', () => {
      expect(getFlowType({ label: 'request' })).toBe('data')
      expect(getFlowType(undefined)).toBe('data')
    })

    it('returns the key when it is a spec value', () => {
      expect(getFlowType({ flowType: 'signal' })).toBe('signal')
      expect(getFlowType({ flowType: 'message' })).toBe('message')
    })

    it('falls back to data for an unknown value', () => {
      expect(getFlowType({ flowType: 'telepathy' })).toBe('data')
    })
  })

  describe('getBoundaryType', () => {
    it('defaults to trust when the key is missing', () => {
      expect(getBoundaryType({})).toBe('trust')
      expect(getBoundaryType(undefined)).toBe('trust')
    })

    it('returns the key when it is a spec value', () => {
      expect(getBoundaryType({ boundaryType: 'network' })).toBe('network')
    })

    it('falls back to trust for an unknown value', () => {
      expect(getBoundaryType({ boundaryType: 'moat' })).toBe('trust')
    })
  })

  describe('getComponentKind', () => {
    it('derives the kind from the node type when the key is missing', () => {
      expect(getComponentKind({}, 'process')).toBe('process')
      expect(getComponentKind({}, 'datastore')).toBe('data-store')
      expect(getComponentKind({}, 'humanActor')).toBe('actor')
      expect(getComponentKind({}, 'systemActor')).toBe('actor')
      expect(getComponentKind({}, 'systemScope')).toBe('system')
      expect(getComponentKind(undefined, undefined)).toBe('component')
    })

    it('returns the key when it is a spec asset type', () => {
      expect(getComponentKind({ kind: 'queue' }, 'datastore')).toBe('queue')
      expect(getComponentKind({ kind: 'api' }, 'process')).toBe('api')
    })

    it('falls back to the node type default for an unknown value', () => {
      expect(getComponentKind({ kind: 'widget' }, 'datastore')).toBe('data-store')
    })

    it('kindForNodeType mirrors the backend category defaults', () => {
      expect(kindForNodeType('process')).toBe('process')
      expect(kindForNodeType('stickyNote')).toBe('component')
    })
  })

  describe('getAuthentication', () => {
    it('returns an empty list when the key is missing', () => {
      expect(getAuthentication({})).toEqual([])
      expect(getAuthentication(undefined)).toEqual([])
    })

    it('returns the list when present', () => {
      expect(getAuthentication({ authentication: ['oauth2', 'mtls'] })).toEqual(['oauth2', 'mtls'])
    })

    it('keeps custom names and drops non-strings', () => {
      expect(getAuthentication({ authentication: ['custom-sso', 7, ''] })).toEqual(['custom-sso'])
    })

    it('reads the retired boolean as unspecified, as the backend sync does', () => {
      expect(getAuthentication({ authenticated: true })).toEqual(['unspecified'])
      expect(getAuthentication({ authenticated: false })).toEqual([])
    })

    it('prefers the list over the retired boolean', () => {
      expect(getAuthentication({ authenticated: true, authentication: ['jwt'] })).toEqual(['jwt'])
    })

    it('knows the spec values and our placeholder', () => {
      expect(isKnownAuthenticationType('oidc')).toBe(true)
      expect(isKnownAuthenticationType('unspecified')).toBe(true)
      expect(isKnownAuthenticationType('password')).toBe(false)
    })
  })
})

describe('isAuthenticated (I5)', () => {
  it('is false for an empty or missing list', () => {
    expect(isAuthenticated([])).toBe(false)
    expect(isAuthenticated(undefined)).toBe(false)
    expect(isAuthenticated(null)).toBe(false)
  })

  it('is false when the list contains none', () => {
    expect(isAuthenticated(['none'])).toBe(false)
    expect(isAuthenticated(['oauth2', 'none'])).toBe(false)
  })

  it('is true for unspecified: authenticated, method not recorded', () => {
    expect(isAuthenticated(['unspecified'])).toBe(true)
  })

  it('is true for any real method', () => {
    expect(isAuthenticated(['mtls'])).toBe(true)
    expect(isAuthenticated(['form', 'totp'])).toBe(true)
  })

  it('answers authorization with the same rule', () => {
    expect(requiresAuthorization(['rbac'])).toBe(true)
    expect(requiresAuthorization(['none'])).toBe(false)
    expect(requiresAuthorization([])).toBe(false)
  })
})
