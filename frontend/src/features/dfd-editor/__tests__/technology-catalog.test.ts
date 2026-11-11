import { describe, expect, it } from 'vitest'
import { buildTechnologyCatalog, findTechnology } from '../lib/technology-catalog'

const catalog = buildTechnologyCatalog([
  { id: 'cloudformation', name: 'AWS CloudFormation', iconSvg: '<svg/>' },
  { id: 's3', name: 'Amazon S3', iconSvg: null },
])

describe('findTechnology', () => {
  it('matches by id', () => {
    expect(findTechnology(catalog, 'cloudformation')?.name).toBe('AWS CloudFormation')
  })

  it('matches by name ignoring case, as legacy diagrams stored the display name', () => {
    expect(findTechnology(catalog, 'amazon s3')?.id).toBe('s3')
  })

  it('gives null for a miss, a blank slug or no catalog', () => {
    expect(findTechnology(catalog, 'custom-thing')).toBeNull()
    expect(findTechnology(catalog, undefined)).toBeNull()
    expect(findTechnology(null, 'cloudformation')).toBeNull()
  })

  it('builds no catalog from an absent list, so the hooks fall back to the API', () => {
    expect(buildTechnologyCatalog(undefined)).toBeNull()
  })
})
