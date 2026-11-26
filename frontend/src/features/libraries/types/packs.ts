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
