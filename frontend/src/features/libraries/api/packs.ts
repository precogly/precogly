/**
 * API hooks for Library Packs.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type {
  LibraryPack,
  LibraryPackListItem,
  PackDependencyCheck,
  PackFilters,
  ValidationResult,
  WaitingFramework,
} from '@/features/libraries/types/packs'

// Query keys
export const packKeys = {
  all: ['packs'] as const,
  lists: () => [...packKeys.all, 'list'] as const,
  list: (filters: PackFilters) => [...packKeys.lists(), filters] as const,
  details: () => [...packKeys.all, 'detail'] as const,
  detail: (id: number) => [...packKeys.details(), id] as const,
  dependencies: (id: number) => [...packKeys.all, 'dependencies', id] as const,
  preview: (id: number) => [...packKeys.all, 'preview', id] as const,
  previewFromSource: (packPath: string) => [...packKeys.all, 'preview-source', packPath] as const,
  availableFromSource: ['packs', 'available-from-source'] as const,
}

// Types for source-based pack operations
export interface SourcePackInfo {
  slug: string
  name: string
  description: string
  version: string
  packType: string
  author: string
  tags: string[]
  path: string
  relativePath: string
  isInDatabase: boolean
  databaseVersion: string | null
  needsUpdate: boolean
  componentCount: number
  threatCount: number
  countermeasureCount: number
  taxonomyCount: number
  /** Entries across the pack's taxonomies, e.g. 116 for CWE. Optional: older servers omit it. */
  taxonomyEntryCount?: number
  frameworkCount?: number
  /** Requirements across the pack's frameworks, e.g. 28 for CRA. */
  requirementCount?: number
  /** DFD templates and worksheets in the pack. */
  templateCount?: number
  dependsOn: Array<{ slug: string; name: string; isImported: boolean }>
  /** "bundled": on this server's disk. "catalog": from the pack library. Optional: older backends omit it. */
  source?: 'bundled' | 'catalog'
}

export interface AvailablePacksResponse {
  packs: SourcePackInfo[]
  total: number
  inDatabase: number
  needsUpdate: number
  /** False when the server has the pack catalog turned off. */
  catalogEnabled?: boolean
  /** False when the catalog could not be fetched. */
  catalogAvailable?: boolean
  /** The library-packs release listed, for example v2026.11.26.1. */
  catalogRelease?: string
  /** "precogly/library-packs", or the host of a self-hosted catalog. */
  catalogSourceName?: string
  /** The release page on GitHub; empty for a self-hosted catalog. */
  catalogReleaseUrl?: string
  /** The packs/ folder at that release on GitHub; empty for a self-hosted catalog. */
  catalogPacksUrl?: string
}

export interface ImportResult {
  success: boolean
  packSlug: string
  packName: string
  version: string
  message: string
  componentsCreated: number
  threatsCreated: number
  countermeasuresCreated: number
  templatesCreated: number
  taxonomiesCreated: number
  errors: string[]
  warnings: string[]
  /** Dependencies imported first, in order, by this request. */
  dependenciesImported?: string[]
  /** Frameworks the imported pack maps to that are not imported yet. */
  waitingFrameworks?: WaitingFramework[]
}

/**
 * The body of a failed import that brought in dependencies first (HTTP 400
 * when a dependency did not validate, 502 when a download failed).
 */
export interface ImportFailureBody {
  error?: string
  /** The dependency that failed; empty when the requested pack itself failed to download. */
  failedDependency?: string
  dependenciesImported?: string[]
  /** Dependencies still waiting, then the requested pack. */
  notImported?: string[]
  validation?: ValidationResult
}

export interface SyncFromSourceResponse {
  results: ImportResult[]
  summary: {
    total: number
    successful: number
    failed: number
  }
  message: string
}

// Types for pack preview
export interface PackPreviewComponent {
  slug: string
  name: string
  category: string
  componentType: string
  description: string
}

export interface PackPreviewThreat {
  slug: string
  name: string
  taxonomyEntries: Array<{ taxonomySlug: string; externalId: string; title: string }>
  severity: string
  description: string
}

export interface PackPreviewCountermeasure {
  slug: string
  name: string
  controlFunctions: string[]
  controlNature: string
  cost: string
  defaultStatus?: string
  description: string
}

export interface PackPreviewRequirement {
  sectionCode: string
  description: string
  frameworkName: string
}

export interface PackPreviewTaxonomyEntry {
  externalId: string
  title: string
  description: string
}

export interface PackPreviewTaxonomy {
  slug: string
  name: string
  description: string
  entryCount: number
  entries: PackPreviewTaxonomyEntry[]
}

export interface PackPreviewResponse {
  pack: {
    slug: string
    name: string
    description: string
    version: string
    packType: string
    author: string
    tags: string[]
  }
  components: PackPreviewComponent[]
  threats: PackPreviewThreat[]
  countermeasures: PackPreviewCountermeasure[]
  requirements: PackPreviewRequirement[]
  taxonomies: PackPreviewTaxonomy[]
}

// Types for pack overlays
export interface OverlayInfo {
  frameworkId: string
  frameworkName: string
  mappingCount: number
  frameworkExists: boolean
}

export interface AvailableOverlaysResponse {
  overlays: OverlayInfo[]
  total: number
  availableCount: number
}

// Build query string from filters
function buildQueryString(filters: PackFilters): string {
  const params = new URLSearchParams()
  if (filters.search) params.append('search', filters.search)
  const query = params.toString()
  return query ? `?${query}` : ''
}

// Query Hooks

/**
 * Fetch list of available packs with optional filters.
 */
export function usePacks(filters: PackFilters = {}) {
  return useQuery({
    queryKey: packKeys.list(filters),
    queryFn: async () => {
      const queryString = buildQueryString(filters)
      const response = await api.get<{ results: LibraryPackListItem[] } | LibraryPackListItem[]>(
        `/packs/${queryString}`
      )
      return Array.isArray(response) ? response : response.results
    },
  })
}

/**
 * Fetch a single pack by ID with full details.
 */
export function usePack(id: number | null) {
  return useQuery({
    queryKey: packKeys.detail(id!),
    queryFn: () => api.get<LibraryPack>(`/packs/${id}/`),
    enabled: id !== null,
  })
}

/**
 * Check dependencies for a pack before import.
 */
export function usePackDependencies(id: number | null) {
  return useQuery({
    queryKey: packKeys.dependencies(id!),
    queryFn: () => api.get<PackDependencyCheck>(`/packs/${id}/check_dependencies/`),
    enabled: id !== null,
  })
}

// =============================================================================
// Source-based pack operations (reading from libraries folder)
// =============================================================================

/**
 * Fetch packs available from the libraries folder (source files).
 * These are packs that exist in the libraries/packs directory,
 * which may or may not be imported into the database yet.
 */
export function useAvailablePacksFromSource() {
  return useQuery({
    queryKey: packKeys.availableFromSource,
    queryFn: () => api.get<AvailablePacksResponse>('/packs/available_from_source/'),
  })
}

/**
 * Sync all packs from the libraries folder to the database.
 * This imports new packs and optionally updates existing ones.
 */
export function useSyncPacksFromSource() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (options: { force?: boolean } = {}) =>
      api.post<SyncFromSourceResponse>('/packs/sync_from_source/', {
        force: options.force ?? false,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: packKeys.all })
      queryClient.invalidateQueries({ queryKey: packKeys.availableFromSource })
    },
  })
}

/**
 * Import a bundled or catalog pack by slug. The server imports its missing
 * dependencies first. Optionally specify which framework overlays to load.
 */
export function useImportSinglePack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      slug,
      force = false,
      selectedOverlays,
      skipValidation = false,
    }: {
      slug: string
      force?: boolean
      selectedOverlays?: string[] | null
      skipValidation?: boolean
    }) =>
      api.post<ImportResult>('/packs/import_single/', {
        slug,
        force,
        selectedOverlays,
        skipValidation,
      }),
    // onSettled, not onSuccess: a failed import may still have imported some
    // dependencies, and the list has to show them.
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: packKeys.all })
      queryClient.invalidateQueries({ queryKey: packKeys.availableFromSource })
      // Also invalidate component library to refresh available technologies
      queryClient.invalidateQueries({ queryKey: ['component-library'] })
    },
  })
}

/**
 * Fetch available framework overlays for a pack before import.
 */
export function usePackOverlays(packPath: string | null) {
  return useQuery({
    queryKey: [...packKeys.all, 'overlays', packPath],
    queryFn: () =>
      api.get<AvailableOverlaysResponse>(
        `/packs/available_overlays/?path=${encodeURIComponent(packPath!)}`
      ),
    enabled: packPath !== null,
  })
}

// =============================================================================
// Pack Validation
// =============================================================================

/**
 * Validate a pack's YAML references without importing (dry-run).
 */
export function useValidatePack() {
  return useMutation({
    mutationFn: ({ slug }: { slug: string }) =>
      api.post<ValidationResult>('/packs/validate/', { slug }),
  })
}

// =============================================================================
// Pack Preview Hooks
// =============================================================================

/**
 * Fetch full pack contents for preview (database packs).
 */
export function usePackPreview(id: number | null) {
  return useQuery({
    queryKey: packKeys.preview(id!),
    queryFn: () => api.get<PackPreviewResponse>(`/packs/${id}/preview/`),
    enabled: id !== null,
  })
}

/**
 * Fetch full pack contents for preview (source packs by path).
 */
export function useSourcePackPreview(packPath: string | null) {
  return useQuery({
    queryKey: packKeys.previewFromSource(packPath!),
    queryFn: () =>
      api.get<PackPreviewResponse>(
        `/packs/preview_from_source/?path=${encodeURIComponent(packPath!)}`
      ),
    enabled: packPath !== null,
  })
}

// =============================================================================
// Pack Unimport
// =============================================================================

export interface UnimportResult {
  pack: {
    id: number
    slug: string
    name: string
    version: string
  }
  toDelete: {
    components: number
    threats: number
    countermeasures: number
    templates: number
    taxonomies: number
    frameworks: number
  }
  dryRun: boolean
  deleted?: boolean
  message: string
}

/**
 * Unimport a pack by deleting all its library items and the pack record.
 */
export function useUnimportPack() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      packId,
      dryRun = false,
    }: {
      packId: number
      dryRun?: boolean
    }) => {
      const params = dryRun ? '?dry_run=true' : ''
      return api.delete<UnimportResult>(`/packs/${packId}/unimport/${params}`)
    },
    onSuccess: (_, { dryRun }) => {
      // Only invalidate queries if this was not a dry run
      if (!dryRun) {
        queryClient.invalidateQueries({ queryKey: packKeys.all })
        queryClient.invalidateQueries({ queryKey: packKeys.availableFromSource })
        queryClient.invalidateQueries({ queryKey: ['component-library'] })
        queryClient.invalidateQueries({ queryKey: ['threat-library'] })
        queryClient.invalidateQueries({ queryKey: ['countermeasure-library'] })
      }
    },
  })
}
