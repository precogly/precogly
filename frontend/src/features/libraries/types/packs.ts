/**
 * Type definitions for Library Packs.
 */

export type PackType = 'technology' | 'threat' | 'countermeasure' | 'compliance' | 'template' | 'full' | 'taxonomy'

export interface PackDependency {
  id: number
  dependsOnPack: number
  dependsOnPackName: string
  dependsOnPackSlug: string
}

export interface PackContentSummary {
  components: number
  threats: number
  countermeasures: number
  templates: number
  taxonomies: number
}

export interface LibraryPack {
  id: number
  slug: string
  name: string
  description: string
  version: string
  packType: PackType
  author: string
  tags: string[]
  isImported: boolean
  dependencies?: PackDependency[]
  contentSummary?: PackContentSummary
  createdAt: string
  updatedAt: string
}

export interface LibraryPackListItem {
  id: number
  slug: string
  name: string
  description: string
  version: string
  packType: PackType
  author: string
  tags: string[]
  isImported: boolean
  /** Frameworks this pack maps to that are not imported yet. Optional: older servers omit it. */
  waitingFrameworks?: WaitingFramework[]
}

/** A framework a pack has mappings for, not imported yet: the mappings are saved until it is. */
export interface WaitingFramework {
  frameworkSlug: string
  mappingCount: number
}

export interface PackDependencyCheck {
  pack: LibraryPackListItem
  dependencies: {
    packId: number
    slug: string
    name: string
    version: string
    isImported: boolean
  }[]
  missingDependencies: string[]
  allSatisfied: boolean
}

export interface PackFilters {
  category?: string
  search?: string
}

export interface ValidationWarning {
  file: string
  field: string
  message: string
  suggestion: string
  /** Set when the warning is only a framework not imported yet: its mappings are saved until it is. */
  waitingForFramework?: string
}

export interface ValidationError {
  file: string
  line: number | null
  refType: string
  reference: string
  message: string
}

export interface ValidationResult {
  success: boolean
  packSlug: string
  packName: string
  version: string
  errors: ValidationError[]
  warnings: ValidationWarning[]
  errorCount: number
  warningCount: number
  /** From validate: dependencies listed but not imported yet. Import brings them in first. */
  pendingDependencies?: string[]
}
