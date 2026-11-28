import type { UnifiedPack } from '../components/unified-pack'

/** A pack for tests; not imported, offered by the catalog, unless overridden. */
export function makePack(overrides: Partial<UnifiedPack>): UnifiedPack {
  const slug = overrides.slug ?? 'pack'
  return {
    slug,
    name: slug.toUpperCase(),
    description: '',
    version: '1.0.0',
    packType: 'full',
    tags: [],
    relativePath: `threat-libraries/${slug}`,
    componentCount: 0,
    threatCount: 0,
    countermeasureCount: 0,
    taxonomyCount: 0,
    taxonomyEntryCount: 0,
    frameworkCount: 0,
    requirementCount: 0,
    templateCount: 0,
    isInDatabase: false,
    isImported: false,
    databaseId: null,
    dependsOn: [],
    source: 'catalog',
    needsUpdate: false,
    databaseVersion: null,
    ...overrides,
  }
}

export function dependency(slug: string, isImported = false) {
  return { slug, name: slug.toUpperCase(), isImported }
}
