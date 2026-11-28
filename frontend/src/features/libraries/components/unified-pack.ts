// Unified pack type that can represent both source and database packs
export interface UnifiedPack {
  slug: string
  name: string
  description: string
  version: string
  packType: string
  tags: string[]
  relativePath: string
  componentCount: number
  threatCount: number
  countermeasureCount: number
  taxonomyCount: number
  taxonomyEntryCount: number
  frameworkCount: number
  requirementCount: number
  templateCount: number
  isInDatabase: boolean
  isImported: boolean
  databaseId: number | null
  dependsOn: Array<{ slug: string; name: string; isImported: boolean }>
  /** Where the pack's files come from. A database-only pack (imported earlier,
   * offered by neither source now) has none. */
  source?: 'bundled' | 'catalog'
  /** In the database at a version that differs from the offered one. */
  needsUpdate: boolean
  /** The imported version, or null when the pack is not imported. */
  databaseVersion: string | null
}
