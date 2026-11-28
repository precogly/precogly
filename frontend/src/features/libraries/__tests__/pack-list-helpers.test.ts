import { describe, expect, it } from 'vitest'

import { ApiError } from '@/lib/api'

import { packCategoryFromPath, serverErrorMessage } from '../components/pack-list-helpers'

describe('packCategoryFromPath', () => {
  it.each([
    ['demo-taxonomies/stride-taxonomy', 'taxonomies', true],
    ['demo-standards/demo-asvs', 'standards', true],
    ['demo-threat-libraries/demo-aws', 'threat-libraries', true],
    ['taxonomies/stride-taxonomy', 'taxonomies', false],
    ['threat-libraries/aws', 'threat-libraries', false],
    ['', '', false],
  ])('%s is category %s, demo %s', (relativePath, category, isDemo) => {
    expect(packCategoryFromPath(relativePath)).toEqual({ category, isDemo })
  })
})

describe('serverErrorMessage', () => {
  it('returns the error text the server sent', () => {
    const error = new ApiError('API Error: 404 Not Found', 404, {
      error: "Source files for pack 'aws' are not available on this server",
    })
    expect(serverErrorMessage(error)).toBe("Source files for pack 'aws' are not available on this server")
  })

  it('returns null without a usable body', () => {
    expect(serverErrorMessage(new ApiError('API Error: 500', 500))).toBeNull()
    expect(serverErrorMessage(new ApiError('API Error: 400', 400, { error: 42 }))).toBeNull()
    expect(serverErrorMessage(new Error('network'))).toBeNull()
    expect(serverErrorMessage(null)).toBeNull()
  })
})
