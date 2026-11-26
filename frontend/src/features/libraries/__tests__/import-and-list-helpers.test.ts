import { describe, expect, it } from 'vitest'

import { ApiError } from '@/lib/api'

import {
  collectPacksToImport,
  dependenciesImportedLine,
  fullVersionOf,
  importButtonLabel,
  importFailureLines,
  isImportFailureBody,
  isNoUsableResponse,
  matchesStatus,
  onlyBundledPacksImported,
  showCatalogUnreachableNotice,
  showDemoContentNotice,
  sortPacksForList,
} from '../components/pack-list-helpers'
import { dependency, makePack } from './pack-fixtures'

describe('collectPacksToImport', () => {
  it('walks a three-level chain, each pack after its own dependencies', () => {
    const stride = makePack({ slug: 'stride', source: 'bundled' })
    const cwe = makePack({ slug: 'cwe', dependsOn: [dependency('stride')] })
    const ai = makePack({ slug: 'ai', dependsOn: [dependency('cwe')] })
    const aws = makePack({ slug: 'aws', dependsOn: [dependency('ai')] })

    const result = collectPacksToImport(aws, [aws, ai, cwe, stride])

    expect(result.packs.map((pack) => pack.slug)).toEqual(['stride', 'cwe', 'ai'])
    expect(result.unavailableDependencies).toEqual([])
  })

  it('lists a dependency shared by two packs once', () => {
    const cwe = makePack({ slug: 'cwe' })
    const ai = makePack({ slug: 'ai', dependsOn: [dependency('cwe')] })
    const aws = makePack({ slug: 'aws', dependsOn: [dependency('cwe'), dependency('ai')] })

    expect(collectPacksToImport(aws, [aws, ai, cwe]).packs.map((pack) => pack.slug)).toEqual(['cwe', 'ai'])
  })

  it('leaves out a dependency that is already imported, and what lies behind it', () => {
    const capec = makePack({ slug: 'capec' })
    const cwe = makePack({ slug: 'cwe', isImported: true, isInDatabase: true, dependsOn: [dependency('capec')] })
    const aws = makePack({ slug: 'aws', dependsOn: [dependency('cwe', true)] })

    expect(collectPacksToImport(aws, [aws, cwe, capec]).packs).toEqual([])
  })

  it('ends on a cycle', () => {
    const one = makePack({ slug: 'one', dependsOn: [dependency('two')] })
    const two = makePack({ slug: 'two', dependsOn: [dependency('one')] })

    expect(collectPacksToImport(one, [one, two]).packs.map((pack) => pack.slug)).toEqual(['two'])
  })

  it('reports a dependency that is neither imported nor offered', () => {
    const aws = makePack({ slug: 'aws', dependsOn: [dependency('ghost'), dependency('known', true)] })

    expect(collectPacksToImport(aws, [aws])).toEqual({ packs: [], unavailableDependencies: ['ghost'] })
  })
})

describe('importButtonLabel', () => {
  it('counts the requested pack and its dependencies', () => {
    expect(importButtonLabel(makePack({}), 4)).toBe('Import 4 packs')
    expect(importButtonLabel(makePack({}), 1)).toBe('Import')
  })

  it('names the version an installed pack is moved to', () => {
    const installed = makePack({ isInDatabase: true, isImported: true, version: '2.1.0', databaseVersion: '2.0.0' })
    expect(importButtonLabel(installed, 1)).toBe('Install 2.1.0')
    expect(importButtonLabel(installed, 2)).toBe('Install 2.1.0 and import 1 pack')
    expect(importButtonLabel(installed, 3)).toBe('Install 2.1.0 and import 2 packs')
  })

  it("names the library's version even when it is the lower one", () => {
    const olderLibrary = makePack({ isInDatabase: true, isImported: true, version: '1.0.0', databaseVersion: '2.0.0' })
    expect(importButtonLabel(olderLibrary, 1)).toBe('Install 1.0.0')
  })
})

describe('status filter and order', () => {
  const imported = makePack({ slug: 'cwe', name: 'cwe', isImported: true, isInDatabase: true })
  const outdated = makePack({
    slug: 'aws',
    name: 'AWS',
    isImported: true,
    isInDatabase: true,
    needsUpdate: true,
    databaseVersion: '3.0.0',
  })
  const notImported = makePack({ slug: 'azure', name: 'Azure' })
  const databaseOnly = makePack({
    slug: 'old',
    name: 'Old pack',
    relativePath: '',
    source: undefined,
    isImported: true,
    isInDatabase: true,
  })
  const packs = [notImported, imported, outdated, databaseOnly]

  it('matchesStatus', () => {
    const slugsFor = (status: Parameters<typeof matchesStatus>[1]) =>
      packs.filter((pack) => matchesStatus(pack, status)).map((pack) => pack.slug)
    expect(slugsFor('all')).toEqual(['azure', 'cwe', 'aws', 'old'])
    expect(slugsFor('imported')).toEqual(['cwe', 'aws', 'old'])
    expect(slugsFor('not-imported')).toEqual(['azure'])
    expect(slugsFor('update-available')).toEqual(['aws'])
  })

  it('sortPacksForList puts imported packs first, then sorts by name ignoring case', () => {
    expect(sortPacksForList(packs).map((pack) => pack.name)).toEqual(['AWS', 'cwe', 'Old pack', 'Azure'])
  })
})

describe('demo content', () => {
  const demoAws = makePack({ slug: 'demo-aws', source: 'bundled', isImported: true, isInDatabase: true })
  const stride = makePack({ slug: 'stride-taxonomy', source: 'bundled', isImported: true, isInDatabase: true })
  const aws = makePack({ slug: 'aws', name: 'AWS' })
  const flagsOn = { catalogEnabled: true, catalogAvailable: true }

  it('onlyBundledPacksImported', () => {
    expect(onlyBundledPacksImported([demoAws, stride, aws])).toBe(true)
    expect(onlyBundledPacksImported([demoAws, { ...aws, isImported: true, isInDatabase: true }])).toBe(false)
    expect(onlyBundledPacksImported([demoAws, makePack({ slug: 'old', source: undefined, isImported: true })])).toBe(
      false,
    )
    expect(onlyBundledPacksImported([aws])).toBe(false)
  })

  it('the notice shows for the security team while only bundled packs are imported', () => {
    expect(showDemoContentNotice(flagsOn, true, [demoAws, stride, aws])).toBe(true)
  })

  it('the notice goes away once a pack from the library repo is imported', () => {
    expect(showDemoContentNotice(flagsOn, true, [demoAws, { ...aws, isImported: true, isInDatabase: true }])).toBe(
      false,
    )
  })

  it('the notice is hidden for other users and when the catalog is off or unreachable', () => {
    expect(showDemoContentNotice(flagsOn, false, [demoAws, aws])).toBe(false)
    expect(showDemoContentNotice({ catalogEnabled: false, catalogAvailable: false }, true, [demoAws])).toBe(false)
    expect(showDemoContentNotice({ catalogEnabled: true, catalogAvailable: false }, true, [demoAws])).toBe(false)
  })

  it('a demo pack links to its full version only when the list offers it', () => {
    expect(fullVersionOf(demoAws, [demoAws, aws])).toBe(aws)
    expect(fullVersionOf(demoAws, [demoAws])).toBeNull()
    expect(fullVersionOf(aws, [demoAws, aws])).toBeNull()
  })
})

describe('the catalog notice', () => {
  it.each([
    [{ catalogEnabled: true, catalogAvailable: false }, true],
    [{ catalogEnabled: true, catalogAvailable: true }, false],
    [{ catalogEnabled: false, catalogAvailable: false }, false],
    [{}, false],
    [undefined, false],
  ])('flags %j show it: %s', (flags, shown) => {
    expect(showCatalogUnreachableNotice(flags)).toBe(shown)
  })
})

describe('a failed import', () => {
  const packs = [makePack({ slug: 'cwe', name: 'CWE' }), makePack({ slug: 'mitre-attack', name: 'MITRE ATT&CK' })]

  it('names what was imported, what failed and what was not imported', () => {
    const body = {
      error: 'x',
      failedDependency: 'mitre-attack',
      dependenciesImported: ['cwe', 'capec'],
      notImported: ['atlas', 'aws'],
    }
    expect(isImportFailureBody(body)).toBe(true)
    expect(importFailureLines(body, packs)).toEqual({
      imported: 'Imported: CWE, capec',
      failed: 'Failed: MITRE ATT&CK',
      notImported: 'Not imported: atlas, aws',
    })
  })

  it('omits a line with nothing in it', () => {
    expect(importFailureLines({ failedDependency: '', dependenciesImported: [], notImported: ['aws'] }, packs)).toEqual({
      imported: null,
      failed: null,
      notImported: 'Not imported: aws',
    })
  })

  it('tells a plain validation body apart', () => {
    expect(isImportFailureBody({ warningCount: 1, errors: [] })).toBe(false)
    expect(isImportFailureBody('Bad Gateway')).toBe(false)
  })

  it("treats the requested pack's own warnings as the Import anyway case, even after dependencies", () => {
    // What the server sends when aws itself warns after its 11 dependencies were imported.
    const requestedPackWarnings = {
      warningCount: 3,
      errors: [],
      dependenciesImported: ['cwe', 'capec'],
      notImported: ['aws'],
    }
    expect(isImportFailureBody(requestedPackWarnings)).toBe(false)
    expect(dependenciesImportedLine(requestedPackWarnings, packs)).toBe('Dependencies already imported: CWE, capec')
    expect(dependenciesImportedLine({ warningCount: 1, dependenciesImported: [] }, packs)).toBeNull()
  })

  it('a download failure of the requested pack itself still counts as a failure body', () => {
    expect(isImportFailureBody({ error: 'x', failedDependency: '', notImported: ['aws'] })).toBe(true)
  })

  it('recognises a request with no usable answer', () => {
    expect(isNoUsableResponse(new TypeError('Failed to fetch'))).toBe(true)
    expect(isNoUsableResponse(new ApiError('API Error: 502', 502, '<html>Bad Gateway</html>'))).toBe(true)
    expect(isNoUsableResponse(new ApiError('API Error: 504', 504, ''))).toBe(true)
    expect(isNoUsableResponse(new ApiError('API Error: 400', 400, { failedDependency: 'cwe' }))).toBe(false)
  })
})
