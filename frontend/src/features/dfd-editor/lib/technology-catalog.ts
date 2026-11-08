/**
 * A small catalog of technologies embedded in a payload (the magic link share
 * page), so diagram nodes can show their icon and name without the component
 * library API, which needs a login. Matched the way the hooks match the API
 * list: by id, then by name ignoring case.
 */

export interface TechnologyCatalogEntry {
  /** The frontend's technology id: the library slug, else the qualified slug, else the row id. */
  id: string
  name: string
  iconSvg: string | null
}

export type TechnologyCatalog = ReadonlyMap<string, TechnologyCatalogEntry>

export function buildTechnologyCatalog(entries: readonly TechnologyCatalogEntry[] | undefined): TechnologyCatalog | null {
  if (!entries) return null
  return new Map(entries.map((entry) => [entry.id, entry]))
}

export function findTechnology(catalog: TechnologyCatalog | null, slug: string | undefined): TechnologyCatalogEntry | null {
  if (!catalog || !slug) return null
  const byId = catalog.get(slug)
  if (byId) return byId
  const wanted = slug.toLowerCase()
  for (const entry of catalog.values()) {
    if (entry.name.toLowerCase() === wanted) return entry
  }
  return null
}
