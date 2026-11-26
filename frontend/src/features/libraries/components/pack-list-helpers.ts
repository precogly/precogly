import { ApiError } from '@/lib/api'
import type { ImportFailureBody, SourcePackInfo } from '@/features/libraries/api/packs'
import type { LibraryPackListItem } from '@/features/libraries/types/packs'
import type { UnifiedPack } from './unified-pack'

/** Folder prefix of the demo packs bundled with the app: demo-taxonomies, demo-standards. */
const DEMO_FOLDER_PREFIX = 'demo-'

/**
 * The Libraries page category of a pack, from the first folder of its path.
 *
 * Bundled demo packs sit in `demo-taxonomies/`, `demo-standards/` and
 * `demo-threat-libraries/`. They belong to the same categories as the full
 * packs, so the prefix is dropped and `isDemo` says it was there. A pack with no
 * path (imported earlier, its files no longer offered) has no category.
 */
export function packCategoryFromPath(relativePath: string): { category: string; isDemo: boolean } {
  const firstFolder = relativePath.split('/')[0] ?? ''
  if (firstFolder.startsWith(DEMO_FOLDER_PREFIX)) {
    return { category: firstFolder.slice(DEMO_FOLDER_PREFIX.length), isDemo: true }
  }
  return { category: firstFolder, isDemo: false }
}

/** The server's `error` text from a failed request, when it sent one. */
export function serverErrorMessage(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null
  const body = error.data as { error?: unknown } | undefined
  return typeof body?.error === 'string' ? body.error : null
}

/**
 * One list of every pack: those offered (bundled or catalog) and those only in
 * the database. Offered packs come first, in the server's order.
 */
export function buildUnifiedPacks(
  sourcePacks: SourcePackInfo[] | undefined,
  databasePacks: LibraryPackListItem[] | undefined,
): UnifiedPack[] {
  const packs: UnifiedPack[] = []
  const seenSlugs = new Set<string>()

  for (const sourcePack of sourcePacks ?? []) {
    const databasePack = databasePacks?.find((candidate) => candidate.slug === sourcePack.slug)
    packs.push({
      slug: sourcePack.slug,
      name: sourcePack.name,
      description: sourcePack.description,
      version: sourcePack.version,
      packType: sourcePack.packType,
      tags: sourcePack.tags,
      relativePath: sourcePack.relativePath,
      componentCount: sourcePack.componentCount,
      threatCount: sourcePack.threatCount,
      countermeasureCount: sourcePack.countermeasureCount ?? 0,
      taxonomyCount: sourcePack.taxonomyCount ?? 0,
      taxonomyEntryCount: sourcePack.taxonomyEntryCount ?? 0,
      frameworkCount: sourcePack.frameworkCount ?? 0,
      requirementCount: sourcePack.requirementCount ?? 0,
      templateCount: sourcePack.templateCount ?? 0,
      isInDatabase: sourcePack.isInDatabase,
      isImported: sourcePack.isInDatabase || (databasePack?.isImported ?? false),
      databaseId: databasePack?.id ?? null,
      dependsOn: sourcePack.dependsOn ?? [],
      source: sourcePack.source ?? 'bundled',
      needsUpdate: sourcePack.needsUpdate ?? false,
      databaseVersion: sourcePack.databaseVersion ?? null,
    })
    seenSlugs.add(sourcePack.slug)
  }

  for (const databasePack of databasePacks ?? []) {
    if (seenSlugs.has(databasePack.slug)) continue
    packs.push({
      slug: databasePack.slug,
      name: databasePack.name,
      description: databasePack.description,
      version: databasePack.version,
      packType: databasePack.packType,
      tags: databasePack.tags,
      relativePath: '',
      componentCount: 0,
      threatCount: 0,
      countermeasureCount: 0,
      taxonomyCount: 0,
      taxonomyEntryCount: 0,
      frameworkCount: 0,
      requirementCount: 0,
      templateCount: 0,
      isInDatabase: true,
      isImported: databasePack.isImported,
      databaseId: databasePack.id,
      dependsOn: [],
      needsUpdate: false,
      databaseVersion: databasePack.version,
    })
  }
  return packs
}

export interface PacksToImport {
  /** Packs the server will import before the requested one, each after its own dependencies. */
  packs: UnifiedPack[]
  /** Dependencies that are not imported and not offered anywhere. */
  unavailableDependencies: string[]
}

/**
 * Every pack an import of `requestedPack` brings in, through every level of
 * dependencies, in the order the server imports them. Already imported packs
 * end a branch. Each slug is visited once, so a cycle cannot loop. The server
 * stays the authority on what it actually imports.
 */
export function collectPacksToImport(requestedPack: UnifiedPack, allPacks: UnifiedPack[]): PacksToImport {
  const packBySlug = new Map(allPacks.map((pack) => [pack.slug, pack]))
  const visitedSlugs = new Set<string>([requestedPack.slug])
  const packs: UnifiedPack[] = []
  const unavailableDependencies: string[] = []

  const visit = (pack: UnifiedPack) => {
    for (const dependency of pack.dependsOn) {
      if (visitedSlugs.has(dependency.slug)) continue
      visitedSlugs.add(dependency.slug)
      const dependencyPack = packBySlug.get(dependency.slug)
      if (!dependencyPack) {
        if (!dependency.isImported) unavailableDependencies.push(dependency.slug)
        continue
      }
      if (dependencyPack.isImported) continue
      visit(dependencyPack)
      packs.push(dependencyPack)
    }
  }
  visit(requestedPack)
  return { packs, unavailableDependencies }
}

/**
 * The import dialog's confirm button. `packCount` counts the requested pack
 * and the packs imported with it.
 */
export function importButtonLabel(pack: UnifiedPack, packCount: number): string {
  const dependencyCount = packCount - 1
  if (pack.isInDatabase) {
    if (dependencyCount <= 0) return `Install ${pack.version}`
    return `Install ${pack.version} and import ${dependencyCount} pack${dependencyCount === 1 ? '' : 's'}`
  }
  return packCount > 1 ? `Import ${packCount} packs` : 'Import'
}

export type PackStatusFilter = 'all' | 'imported' | 'not-imported' | 'update-available'

export const PACK_STATUS_LABELS: Record<PackStatusFilter, string> = {
  all: 'All statuses',
  imported: 'Imported',
  'not-imported': 'Not imported',
  'update-available': 'Update available',
}

/** "Imported" includes database-only packs, which a category filter hides. */
export function matchesStatus(pack: UnifiedPack, status: PackStatusFilter): boolean {
  switch (status) {
    case 'imported':
      return pack.isImported
    case 'not-imported':
      return !pack.isImported
    case 'update-available':
      return pack.isImported && pack.needsUpdate
    default:
      return true
  }
}

/** Imported packs first, then by name, ignoring case. */
export function sortPacksForList(packs: UnifiedPack[]): UnifiedPack[] {
  return [...packs].sort((first, second) => {
    if (first.isImported !== second.isImported) return first.isImported ? -1 : 1
    return first.name.localeCompare(second.name, undefined, { sensitivity: 'base' })
  })
}

/**
 * True when at least one pack is imported and every imported pack is a bundled
 * one. A database-only pack has no source, so it makes this false.
 */
export function onlyBundledPacksImported(allPacks: UnifiedPack[]): boolean {
  const importedPacks = allPacks.filter((pack) => pack.isImported)
  return importedPacks.length > 0 && importedPacks.every((pack) => pack.source === 'bundled')
}

/** The full pack each bundled demo pack was cut from. */
const FULL_VERSION_SLUGS: Record<string, string> = {
  'demo-aws': 'aws',
  'demo-asvs': 'owasp-asvs',
}

/** The full version of a demo pack, when the list offers it. */
export function fullVersionOf(pack: UnifiedPack, allPacks: UnifiedPack[]): UnifiedPack | null {
  const fullSlug = FULL_VERSION_SLUGS[pack.slug]
  if (!fullSlug) return null
  return allPacks.find((candidate) => candidate.slug === fullSlug) ?? null
}

/**
 * A failed import body from a dependency or a download (it names
 * `failedDependency`, empty when the requested pack's own download failed).
 * A body without it is the requested pack's own validation result, which may
 * still list the dependencies imported before it: that one is the usual
 * warnings dialog with "Import anyway".
 */
export function isImportFailureBody(data: unknown): data is ImportFailureBody {
  return typeof data === 'object' && data !== null && 'failedDependency' in data
}

/** "Already imported: CWE, CAPEC" for the requested pack's own warnings dialog, or null. */
export function dependenciesImportedLine(data: unknown, allPacks: UnifiedPack[]): string | null {
  if (typeof data !== 'object' || data === null || !('dependenciesImported' in data)) return null
  const slugs = (data as { dependenciesImported?: unknown }).dependenciesImported
  if (!Array.isArray(slugs) || slugs.length === 0) return null
  const names = slugs.map((slug) => allPacks.find((pack) => pack.slug === slug)?.name ?? String(slug))
  return `Dependencies already imported: ${names.join(', ')}`
}

/**
 * The lines shown after a failed import: what was imported, what failed and
 * what was not imported. Pack names come from the list; the slug when the list
 * lacks the pack. A line is null when it has nothing to say.
 */
export function importFailureLines(
  body: ImportFailureBody,
  allPacks: UnifiedPack[],
): { imported: string | null; failed: string | null; notImported: string | null } {
  const nameOf = (slug: string) => allPacks.find((pack) => pack.slug === slug)?.name ?? slug
  const listOf = (slugs: string[] | undefined) => (slugs?.length ? slugs.map(nameOf).join(', ') : null)
  const imported = listOf(body.dependenciesImported)
  const notImported = listOf(body.notImported)
  return {
    imported: imported && `Imported: ${imported}`,
    failed: body.failedDependency ? `Failed: ${nameOf(body.failedDependency)}` : null,
    notImported: notImported && `Not imported: ${notImported}`,
  }
}

/**
 * True when a request got no usable answer: the network failed, or a gateway
 * (a killed worker gives 502 or 504) sent no JSON. The API client throws a
 * plain TypeError in both cases, since it cannot read the body; an ApiError
 * whose body is not an object counts too.
 */
export function isNoUsableResponse(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  return typeof error.data !== 'object' || error.data === null
}

export const NO_RESPONSE_MESSAGE =
  'The import did not finish. Some packs may have been imported. Reload to check.'

/** The catalog flags the list endpoint returns. Older servers omit them. */
export interface CatalogFlags {
  catalogEnabled?: boolean
  catalogAvailable?: boolean
}

/** "The pack library could not be reached": the catalog is on but the fetch failed. */
export function showCatalogUnreachableNotice(flags: CatalogFlags | undefined): boolean {
  return flags?.catalogEnabled === true && flags.catalogAvailable === false
}

/**
 * "You are using demo content": for the security team, while every imported
 * pack is a bundled one and the full packs can actually be imported.
 */
export function showDemoContentNotice(
  flags: CatalogFlags | undefined,
  isSecurityTeam: boolean,
  allPacks: UnifiedPack[],
): boolean {
  return (
    isSecurityTeam &&
    flags?.catalogEnabled === true &&
    flags.catalogAvailable === true &&
    onlyBundledPacksImported(allPacks)
  )
}

function counted(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`
}

/** "a", "a and b", "a, b and c" */
function joinWithAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join('')
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
}

/**
 * What importing a pack brings in, with counts, for the import dialog. Only
 * counts above zero are named, then one sentence on what the pack does.
 *
 *   AWS:  "41 components, 171 threats, 188 countermeasures and 9 diagram templates. The
 *          components go into the palette, and their threats are suggested when you use them."
 *   CRA:  "1 framework with 28 requirements. They appear in compliance reports, ..."
 *   CWE:  "1 taxonomy with 116 entries. Threats from other packs are tagged with them."
 */
export function packContentsSummary(pack: UnifiedPack): string {
  const isTemplatePack = pack.packType === 'template'
  const parts: string[] = []
  if (pack.componentCount > 0) parts.push(counted(pack.componentCount, 'component'))
  if (pack.threatCount > 0) parts.push(counted(pack.threatCount, 'threat'))
  if (pack.countermeasureCount > 0) parts.push(counted(pack.countermeasureCount, 'countermeasure'))
  if (pack.frameworkCount > 0) {
    parts.push(`${counted(pack.frameworkCount, 'framework')} with ${counted(pack.requirementCount, 'requirement')}`)
  }
  if (pack.taxonomyCount > 0) {
    parts.push(
      `${counted(pack.taxonomyCount, 'taxonomy', 'taxonomies')} with ${counted(pack.taxonomyEntryCount, 'entry', 'entries')}`,
    )
  }
  if (pack.templateCount > 0 && !isTemplatePack) parts.push(counted(pack.templateCount, 'diagram template'))

  if (isTemplatePack && pack.templateCount > 0) {
    return `${counted(pack.templateCount, 'template')}, offered when you create a diagram.`
  }
  if (parts.length === 0) {
    return 'Use Preview to see what this pack contains.'
  }

  const contents = `${joinWithAnd(parts)}.`
  if (pack.threatCount > 0) {
    return pack.componentCount > 0
      ? `${contents} The components go into the palette, and their threats are suggested when you use them.`
      : `${contents} Its threats are suggested for matching components.`
  }
  if (pack.componentCount > 0) {
    return `${contents} The components go into the palette. This pack has no threats of its own.`
  }
  if (pack.frameworkCount > 0) {
    return `${contents} They appear in compliance reports, and packs that map to them link their countermeasures to them.`
  }
  if (pack.taxonomyCount > 0) {
    return `${contents} Threats from other packs are tagged with them.`
  }
  return contents
}
