import { describe, expect, it } from 'vitest'

import { packContentsSummary } from '../components/pack-list-helpers'
import { makePack } from './pack-fixtures'

describe('packContentsSummary', () => {
  it('a threat library names every count and what it adds', () => {
    const aws = makePack({ componentCount: 41, threatCount: 171, countermeasureCount: 188, templateCount: 9 })
    expect(packContentsSummary(aws)).toBe(
      '41 components, 171 threats, 188 countermeasures and 9 diagram templates. ' +
        'The components go into the palette, and their threats are suggested when you use them.',
    )
  })

  it('a pack of components says it has no threats', () => {
    const azure = makePack({ packType: 'technology', componentCount: 45, templateCount: 4 })
    expect(packContentsSummary(azure)).toBe(
      '45 components and 4 diagram templates. The components go into the palette. This pack has no threats of its own.',
    )
  })

  it('a compliance standard counts frameworks and requirements', () => {
    expect(packContentsSummary(makePack({ packType: 'compliance', frameworkCount: 1, requirementCount: 28 }))).toBe(
      '1 framework with 28 requirements. They appear in compliance reports, ' +
        'and packs that map to them link their countermeasures to them.',
    )
    expect(packContentsSummary(makePack({ packType: 'compliance', frameworkCount: 2, requirementCount: 38 }))).toMatch(
      /^2 frameworks with 38 requirements\./,
    )
  })

  it('a taxonomy counts its entries', () => {
    expect(packContentsSummary(makePack({ packType: 'taxonomy', taxonomyCount: 1, taxonomyEntryCount: 116 }))).toBe(
      '1 taxonomy with 116 entries. Threats from other packs are tagged with them.',
    )
    expect(packContentsSummary(makePack({ packType: 'taxonomy', taxonomyCount: 1, taxonomyEntryCount: 1 }))).toMatch(
      /^1 taxonomy with 1 entry\./,
    )
  })

  it('a worksheet pack names its templates', () => {
    expect(packContentsSummary(makePack({ packType: 'template', templateCount: 1 }))).toBe(
      '1 template, offered when you create a diagram.',
    )
  })

  it('a pack with nothing counted points to Preview', () => {
    expect(packContentsSummary(makePack({ relativePath: '', source: undefined }))).toBe(
      'Use Preview to see what this pack contains.',
    )
  })
})
