import { describe, expect, it } from 'vitest'
import type { TaxonomyEntry } from '@/types/domain'
import {
  MAX_CHIP_ENTRIES,
  chipGroups,
  diffTaxonomyLinks,
  fixedEntryHint,
  fixedTaxonomyEntries,
  groupTaxonomyEntries,
  methodologyTaxonomySlugs,
  orderedSearchGroups,
  taxonomyEntryKey,
  taxonomyEntryLabel,
  taxonomyEntrySearchText,
  toggleEntryId,
} from '../components/threat-analysis/taxonomy-picker-utils'

let nextId = 1
function entry(taxonomySlug: string, taxonomyName: string, externalId: string, title: string): TaxonomyEntry {
  return { id: nextId++, taxonomySlug, taxonomyName, externalId, title }
}

const attack = Array.from({ length: MAX_CHIP_ENTRIES + 5 }, (_, index) =>
  entry('mitre-attack', 'ATT&CK Enterprise Techniques', `T10${index}`, `Technique ${index}`)
)
const stride = ['spoofing', 'tampering', 'repudiation'].map((id) => entry('stride', 'STRIDE Threat Model', id, id))
const capec = [entry('capec', 'CAPEC Attack Patterns', '66', 'SQL Injection')]
const groups = groupTaxonomyEntries([...attack, ...stride, ...capec])

describe('methodology taxonomies', () => {
  it('match an installed taxonomy by the lowercase methodology name', () => {
    expect(methodologyTaxonomySlugs(['STRIDE', 'PASTA'], groups)).toEqual(['stride'])
  })

  it('show only small taxonomies as chips', () => {
    expect(chipGroups(groups, ['stride', 'mitre-attack']).map((group) => group.slug)).toEqual(['stride'])
  })

  it('put the methodology taxonomies first in search, then the rest by name', () => {
    expect(orderedSearchGroups(groups, ['stride']).map((group) => group.slug)).toEqual([
      'stride',
      'mitre-attack',
      'capec',
    ])
  })

  it('with no matching methodology, search lists everything by name and there are no chips', () => {
    const quick = methodologyTaxonomySlugs(['PASTA'], groups)
    expect(chipGroups(groups, quick)).toEqual([])
    expect(orderedSearchGroups(groups, quick).map((group) => group.slug)).toEqual(['mitre-attack', 'capec', 'stride'])
  })
})

describe('labels and search', () => {
  it('show the id and title, except for STRIDE', () => {
    expect(taxonomyEntryLabel({ taxonomySlug: 'mitre-attack', externalId: 'T1005', title: 'Data from Local System' })).toBe(
      'T1005 Data from Local System'
    )
    expect(taxonomyEntryLabel({ taxonomySlug: 'capec', externalId: '66', title: 'SQL Injection' })).toBe(
      'CAPEC-66 SQL Injection'
    )
    expect(taxonomyEntryLabel({ taxonomySlug: 'stride', externalId: 'tampering', title: 'Tampering' })).toBe('Tampering')
  })

  it('search matches the id, the short label and the title', () => {
    const text = taxonomyEntrySearchText(capec[0])
    expect(text).toContain('66')
    expect(text).toContain('capec-66')
    expect(text).toContain('sql injection')
  })
})

describe('selection', () => {
  it('toggles an id in and out, keeping the order', () => {
    expect(toggleEntryId([3, 5], 7)).toEqual([3, 5, 7])
    expect(toggleEntryId([3, 5, 7], 5)).toEqual([3, 7])
  })

  it('diffs instance links against the wanted ids', () => {
    const links = [
      { id: 100, taxonomyEntry: 3 },
      { id: 101, taxonomyEntry: 5 },
    ]
    expect(diffTaxonomyLinks(links, [5, 9])).toEqual({ entryIdsToCreate: [9], linkIdsToDelete: [100] })
    expect(diffTaxonomyLinks(links, [])).toEqual({ entryIdsToCreate: [], linkIdsToDelete: [100, 101] })
  })
})

describe('fixed categories', () => {
  const library: TaxonomyEntry = { id: 1, taxonomySlug: 'stride', externalId: 'spoofing', title: 'Spoofing', source: 'library' }
  const snapshot: TaxonomyEntry = { taxonomySlug: 'mitre-attack', externalId: 'T1005', title: 'Data', source: 'snapshot' }
  const instance: TaxonomyEntry = { id: 2, taxonomySlug: 'capec', externalId: '66', title: 'SQLi', source: 'instance' }
  const unmarked: TaxonomyEntry = { id: 3, taxonomySlug: 'capec', externalId: '1', title: 'One' }

  it('keep library, snapshot and unmarked entries, and leave out editable instance ones', () => {
    expect(fixedTaxonomyEntries([library, snapshot, instance, unmarked])).toEqual([library, snapshot, unmarked])
    expect(fixedTaxonomyEntries(undefined)).toEqual([])
  })

  it('match entries by taxonomy and external id, since snapshots have no id', () => {
    expect(taxonomyEntryKey(snapshot)).toBe('mitre-attack:T1005')
  })

  it('explain why a snapshot entry is fixed', () => {
    expect(fixedEntryHint(snapshot)).toContain('not installed')
    expect(fixedEntryHint(library)).toBe('From the library threat')
  })
})
