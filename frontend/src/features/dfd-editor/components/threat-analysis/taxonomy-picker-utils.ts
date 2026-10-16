/**
 * Rules for the threat category picker (TaxonomyCategoryPicker).
 *
 * The model's methodologies decide which taxonomies are one click away: a
 * methodology whose lowercase name is an installed taxonomy slug ("STRIDE"
 * and `stride`) shows that taxonomy's entries as chips, when it is small
 * enough to show whole. Every installed taxonomy is also searchable, grouped
 * by taxonomy, with the quick ones first.
 */
import { formatTaxonomyEntryLabel, type TaxonomyEntry } from '@/types/domain'

/** A taxonomy with more entries than this is search-only, never chips. */
export const MAX_CHIP_ENTRIES = 20

export interface TaxonomyGroup {
  slug: string
  name: string
  entries: TaxonomyEntry[]
}

/** Installed taxonomies, grouped, keeping the API's entry order inside each. */
export function groupTaxonomyEntries(entries: TaxonomyEntry[]): TaxonomyGroup[] {
  const groups = new Map<string, TaxonomyGroup>()
  for (const entry of entries) {
    let group = groups.get(entry.taxonomySlug)
    if (!group) {
      group = { slug: entry.taxonomySlug, name: entry.taxonomyName ?? entry.taxonomySlug, entries: [] }
      groups.set(entry.taxonomySlug, group)
    }
    group.entries.push(entry)
  }
  return [...groups.values()]
}

/** Slugs of the installed taxonomies that match the model's methodologies, in methodology order. */
export function methodologyTaxonomySlugs(methodologies: string[], groups: TaxonomyGroup[]): string[] {
  const installed = new Set(groups.map((group) => group.slug))
  const slugs: string[] = []
  for (const methodology of methodologies) {
    const slug = methodology.trim().toLowerCase()
    if (installed.has(slug) && !slugs.includes(slug)) slugs.push(slug)
  }
  return slugs
}

/** The taxonomies shown as chips: the methodology ones small enough to show whole. */
export function chipGroups(groups: TaxonomyGroup[], quickSlugs: string[]): TaxonomyGroup[] {
  return quickSlugs
    .map((slug) => groups.find((group) => group.slug === slug))
    .filter((group): group is TaxonomyGroup => !!group && group.entries.length <= MAX_CHIP_ENTRIES)
}

/** Groups for the search list: the methodology taxonomies first, then the rest by name. */
export function orderedSearchGroups(groups: TaxonomyGroup[], quickSlugs: string[]): TaxonomyGroup[] {
  const quick = quickSlugs
    .map((slug) => groups.find((group) => group.slug === slug))
    .filter((group): group is TaxonomyGroup => !!group)
  const rest = groups
    .filter((group) => !quickSlugs.includes(group.slug))
    .sort((left, right) => left.name.localeCompare(right.name))
  return [...quick, ...rest]
}

/**
 * The label in lists and chips. STRIDE shows its category name; every other
 * taxonomy shows its id and title ("T1005 Data from Local System"), since an
 * id alone means little to most people.
 */
export function taxonomyEntryLabel(entry: Pick<TaxonomyEntry, 'taxonomySlug' | 'externalId' | 'title'>): string {
  const shortLabel = formatTaxonomyEntryLabel(entry)
  if (entry.taxonomySlug === 'stride' || !entry.title || entry.title === shortLabel) return shortLabel
  return `${shortLabel} ${entry.title}`
}

/** The text the search box matches: id, short label and title. */
export function taxonomyEntrySearchText(entry: TaxonomyEntry): string {
  return `${entry.externalId} ${formatTaxonomyEntryLabel(entry)} ${entry.title}`.toLowerCase()
}

/** Toggle one entry id in a selection, keeping the order. */
export function toggleEntryId(selectedIds: number[], entryId: number): number[] {
  return selectedIds.includes(entryId)
    ? selectedIds.filter((selectedId) => selectedId !== entryId)
    : [...selectedIds, entryId]
}

/** What to create and delete to make a threat's instance links equal `wantedEntryIds`. */
export function diffTaxonomyLinks(
  currentLinks: { id: number; taxonomyEntry: number }[],
  wantedEntryIds: number[]
): { entryIdsToCreate: number[]; linkIdsToDelete: number[] } {
  const currentEntryIds = new Set(currentLinks.map((link) => link.taxonomyEntry))
  const wanted = new Set(wantedEntryIds)
  return {
    entryIdsToCreate: wantedEntryIds.filter((entryId) => !currentEntryIds.has(entryId)),
    linkIdsToDelete: currentLinks.filter((link) => !wanted.has(link.taxonomyEntry)).map((link) => link.id),
  }
}

/**
 * The categories of a threat's merged taxonomy list that are not edited here:
 * the library threat's own, and snapshot ones (kept from a library or taxonomy
 * that is not installed). Instance categories are edited, so they are left out.
 */
export function fixedTaxonomyEntries(entries: TaxonomyEntry[] | undefined): TaxonomyEntry[] {
  return (entries ?? []).filter((entry) => entry.source !== 'instance')
}

/** Identity of an entry across installed and snapshot rows (snapshot rows have no id). */
export function taxonomyEntryKey(entry: Pick<TaxonomyEntry, 'taxonomySlug' | 'externalId'>): string {
  return `${entry.taxonomySlug}:${entry.externalId}`
}

/** Why a category is shown fixed. */
export function fixedEntryHint(entry: Pick<TaxonomyEntry, 'source'>): string {
  return entry.source === 'snapshot'
    ? 'Kept from a library that is not installed'
    : 'From the library threat'
}
