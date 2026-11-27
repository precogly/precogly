import { useState, useMemo, useEffect } from 'react'
import { Info, Package, Search, WifiOff, X } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ApiError } from '@/lib/api'
import { PreviewPackDialog } from './PreviewPackDialog'
import { ImportPackDialog } from './ImportPackDialog'
import { ValidationWarningsDialog, type FailedImportSummary } from './ValidationWarningsDialog'
import { CatalogPackCard } from './CatalogPackCard'
import {
  useAvailablePacksFromSource,
  useImportSinglePack,
  useValidatePack,
  usePacks,
} from '@/features/libraries/api/packs'
import type { PackFilters, ValidationResult } from '@/features/libraries/types/packs'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import type { UnifiedPack } from './unified-pack'
import {
  NO_RESPONSE_MESSAGE,
  PACK_STATUS_LABELS,
  buildUnifiedPacks,
  catalogSourceInfo,
  dependenciesImportedLine,
  fullVersionOf,
  importFailureLines,
  isImportFailureBody,
  isNoUsableResponse,
  matchesStatus,
  packCategoryFromPath,
  packSourceUrl,
  showCatalogUnreachableNotice,
  showDemoContentNotice,
  sortPacksForList,
  type PackStatusFilter,
} from './pack-list-helpers'

export function CatalogView() {
  const { isSecurityTeam } = useWorkspace()
  const [filters, setFilters] = useState<PackFilters>({})
  const [searchInput, setSearchInput] = useState('')
  // Kept out of `filters`, which usePacks sends to the server.
  const [statusFilter, setStatusFilter] = useState<PackStatusFilter>('all')
  const [catalogNoticeDismissed, setCatalogNoticeDismissed] = useState(false)
  const [previewPackId, setPreviewPackId] = useState<number | null>(null)
  const [previewPackPath, setPreviewPackPath] = useState<string | null>(null)
  const [previewIsCatalogPack, setPreviewIsCatalogPack] = useState(false)
  const [previewSourceLink, setPreviewSourceLink] = useState<{ label: string; url: string } | null>(null)
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false)
  const [importingSlug, setImportingSlug] = useState<string | null>(null)
  const [installDialogPack, setInstallDialogPack] = useState<UnifiedPack | null>(null)
  // Validation dialog state
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null)
  const [validationDialogOpen, setValidationDialogOpen] = useState(false)
  const [validationPackSlug, setValidationPackSlug] = useState<string | null>(null)
  const [failedImport, setFailedImport] = useState<FailedImportSummary | null>(null)
  const [validationProgressLine, setValidationProgressLine] = useState<string | null>(null)

  const { data: dbPacks, isLoading: isLoadingDb } = usePacks(filters)
  const { data: sourcePacks, isLoading: isLoadingSource } = useAvailablePacksFromSource()

  const importMutation = useImportSinglePack()
  const validateMutation = useValidatePack()
  const [validatingSlug, setValidatingSlug] = useState<string | null>(null)

  // Debounced search: update filters after user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => ({ ...prev, search: searchInput || undefined }))
    }, 300)
    return () => clearTimeout(timer)
  }, [searchInput])

  // Category labels derived from the first segment of relativePath; the bundled
  // demo packs' `demo-` prefix is dropped (packCategoryFromPath).
  const categoryLabels: Record<string, string> = {
    taxonomies: 'Taxonomies',
    standards: 'Standards',
    'threat-libraries': 'Threat Libraries',
  }

  // Every pack, unfiltered: the import dialog walks dependencies over it, and
  // the notices and "Full version" links look across it.
  const allPacks = useMemo(() => buildUnifiedPacks(sourcePacks?.packs, dbPacks), [sourcePacks, dbPacks])

  const visiblePacks = useMemo(() => {
    let filtered = allPacks
    if (filters.search) {
      const search = filters.search.toLowerCase()
      filtered = filtered.filter(
        (p) =>
          p.name.toLowerCase().includes(search) ||
          p.description.toLowerCase().includes(search) ||
          p.tags.some((t) => t.toLowerCase().includes(search))
      )
    }
    if (filters.category) {
      // A pack with no path (imported earlier, files no longer offered) has no
      // category, so a category filter hides it; the "Imported" status finds it.
      filtered = filtered.filter((p) => packCategoryFromPath(p.relativePath).category === filters.category)
    }
    filtered = filtered.filter((p) => matchesStatus(p, statusFilter))
    return sortPacksForList(filtered)
  }, [allPacks, filters, statusFilter])

  const catalogSource = catalogSourceInfo(sourcePacks)
  const catalogUnreachable = showCatalogUnreachableNotice(sourcePacks) && !catalogNoticeDismissed
  const showDemoNotice = showDemoContentNotice(sourcePacks, isSecurityTeam, allPacks)

  const handleFilterChange = (key: keyof PackFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value === 'all' ? undefined : value,
    }))
  }

  const handleShowFullVersion = (fullPack: UnifiedPack) => {
    setSearchInput(fullPack.name)
    setFilters((prev) => ({ ...prev, category: undefined }))
    setStatusFilter('all')
  }

  const handleImportClick = (pack: UnifiedPack) => {
    // Open the import dialog to show overlay options
    setInstallDialogPack(pack)
  }

  const packName = (slug: string) => allPacks.find((p) => p.slug === slug)?.name ?? slug

  const handleImportConfirm = async (
    pack: UnifiedPack,
    selectedOverlays: string[] | null
  ) => {
    setImportingSlug(pack.slug)
    setInstallDialogPack(null)
    try {
      const result = await importMutation.mutateAsync({
        slug: pack.slug,
        force: pack.isInDatabase,
        selectedOverlays,
      })
      const dependencyCount = result.dependenciesImported?.length ?? 0
      const importedWhat =
        dependencyCount > 0
          ? `${pack.name} and ${dependencyCount} ${dependencyCount === 1 ? 'dependency' : 'dependencies'}`
          : pack.name
      if (result.warnings && result.warnings.length > 0) {
        toast.warning(
          `Imported ${importedWhat} with ${result.warnings.length} warning(s)`,
          {
            description:
              result.warnings[0] +
              (result.warnings.length > 1
                ? ` (+${result.warnings.length - 1} more)`
                : ''),
          }
        )
      } else {
        toast.success(dependencyCount > 0 ? `Imported ${importedWhat}` : `Successfully imported ${pack.name}`)
      }
    } catch (error: unknown) {
      if (isNoUsableResponse(error)) {
        toast.error(NO_RESPONSE_MESSAGE)
        return
      }
      const apiError = error as ApiError

      // A dependency failed, or a download failed after some packs were imported.
      // Checked before the validation branch: its body nests the validation.
      if (isImportFailureBody(apiError.data)) {
        const failureBody = apiError.data
        const lines = importFailureLines(failureBody, allPacks)
        const summaryLines = [lines.imported, lines.failed, lines.notImported].filter(
          (line): line is string => line !== null
        )
        if (apiError.status === 502 || !failureBody.validation) {
          toast.error(failureBody.error ?? 'Import failed', { description: summaryLines.join(' ') })
          return
        }
        setValidationResult(failureBody.validation)
        setValidationPackSlug(null)
        setFailedImport({
          dependencyName: packName(failureBody.failedDependency ?? ''),
          lines: summaryLines,
        })
        setValidationDialogOpen(true)
        return
      }
      const errorData = apiError.data as Record<string, unknown>

      // Show validation dialog for both 422 (warnings) and 400 (errors from validation)
      if ((apiError.status === 422 || apiError.status === 400) && 'warningCount' in errorData) {
        setValidationResult(errorData as unknown as ValidationResult)
        setValidationPackSlug(pack.slug)
        setFailedImport(null)
        setValidationProgressLine(dependenciesImportedLine(errorData, allPacks))
        setValidationDialogOpen(true)
        return
      }
      const message = (errorData.error ?? errorData.message) as string | undefined
      toast.error(message || 'Import failed')
    } finally {
      setImportingSlug(null)
    }
  }

  const handlePreview = (pack: UnifiedPack) => {
    if (pack.databaseId) {
      setPreviewPackId(pack.databaseId)
      setPreviewPackPath(null)
    } else {
      setPreviewPackId(null)
      setPreviewPackPath(pack.relativePath)
    }
    setPreviewIsCatalogPack(pack.source === 'catalog')
    setPreviewSourceLink(
      pack.source === 'catalog' && catalogSource
        ? { label: `${catalogSource.name}, packs/${pack.relativePath}`, url: packSourceUrl(catalogSource, pack.relativePath) }
        : null,
    )
    setPreviewDialogOpen(true)
  }

  const handleValidate = async (pack: UnifiedPack) => {
    setValidatingSlug(pack.slug)
    try {
      const result = await validateMutation.mutateAsync({ slug: pack.slug })
      if (result.errorCount > 0 || result.warningCount > 0) {
        setValidationResult(result)
        setValidationPackSlug(pack.slug)
        setFailedImport(null)
        setValidationDialogOpen(true)
      } else {
        toast.success('Validation passed: no issues found')
      }
    } catch (error: unknown) {
      const message = error instanceof ApiError ? (error.data as { error?: string } | undefined)?.error : undefined
      toast.error(message ?? 'Validation request failed')
    } finally {
      setValidatingSlug(null)
    }
  }

  const isLoading = isLoadingDb || isLoadingSource

  return (
    <div className="space-y-6">
      {catalogUnreachable && (
        <Alert data-testid="catalog-unreachable-notice">
          <WifiOff />
          <AlertDescription className="flex items-start justify-between gap-2">
            <span>The pack library could not be reached. Bundled and imported packs are shown.</span>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0"
              onClick={() => setCatalogNoticeDismissed(true)}
              aria-label="Dismiss"
            >
              <X className="h-4 w-4" />
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {showDemoNotice && (
        <Alert data-testid="demo-content-notice">
          <Info />
          <AlertDescription>You are using demo content. Import the full packs for real work.</AlertDescription>
        </Alert>
      )}

      {catalogSource && (
        <p className="text-sm text-muted-foreground" data-testid="catalog-source-line">
          Full packs come from{' '}
          {catalogSource.releaseUrl ? (
            <a
              href={catalogSource.releaseUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline underline-offset-2"
            >
              {catalogSource.name}
            </a>
          ) : (
            <span className="font-medium">{catalogSource.name}</span>
          )}
          {catalogSource.onGitHub ? ' on GitHub' : ''}, release {catalogSource.release}.
        </p>
      )}

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search packs..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select
          value={filters.category ?? 'all'}
          onValueChange={(value) => handleFilterChange('category', value)}
        >
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {Object.entries(categoryLabels).map(([key, label]) => (
              <SelectItem key={key} value={key}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={(value) => setStatusFilter(value as PackStatusFilter)}>
          <SelectTrigger className="w-[170px]" data-testid="pack-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(PACK_STATUS_LABELS).map(([key, label]) => (
              <SelectItem key={key} value={key}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Result count */}
      {!isLoading && (
        <p className="text-sm text-muted-foreground">
          Showing {visiblePacks.length} pack{visiblePacks.length !== 1 ? 's' : ''}
        </p>
      )}

      {/* Pack Grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-48 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      ) : visiblePacks.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {visiblePacks.map((pack) => (
            <CatalogPackCard
              key={pack.slug}
              pack={pack}
              onImport={handleImportClick}
              onPreview={handlePreview}
              onValidate={handleValidate}
              isImporting={importingSlug === pack.slug}
              isValidating={validatingSlug === pack.slug}
              isSecurityTeam={isSecurityTeam}
              fullVersionPack={fullVersionOf(pack, allPacks)}
              onShowFullVersion={handleShowFullVersion}
              catalogSource={catalogSource}
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-12">
          <Package className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-medium mb-2">No packs found</h3>
          <p className="text-muted-foreground">
            {filters.search || filters.category || statusFilter !== 'all'
              ? 'Try adjusting your search or filters.'
              : 'No library packs are available yet.'}
          </p>
        </div>
      )}

      <PreviewPackDialog
        packId={previewPackId}
        packPath={previewPackPath}
        isCatalogPack={previewIsCatalogPack}
        sourceLink={previewSourceLink}
        open={previewDialogOpen}
        onOpenChange={setPreviewDialogOpen}
      />

      <ImportPackDialog
        key={installDialogPack?.slug ?? 'none'}
        pack={installDialogPack}
        allPacks={allPacks}
        catalogSource={catalogSource}
        open={installDialogPack !== null}
        onOpenChange={(open) => !open && setInstallDialogPack(null)}
        onConfirm={handleImportConfirm}
      />

      <ValidationWarningsDialog
        validationResult={validationResult}
        failedImport={failedImport}
        progressLine={validationProgressLine}
        open={validationDialogOpen}
        onOpenChange={(open) => {
          setValidationDialogOpen(open)
          if (!open) {
            setValidationResult(null)
            setValidationPackSlug(null)
            setFailedImport(null)
            setValidationProgressLine(null)
          }
        }}
        onImportAnyway={
          validationPackSlug
            ? async () => {
                try {
                  const result = await importMutation.mutateAsync({
                    slug: validationPackSlug,
                    force: true,
                    skipValidation: true,
                  })
                  setValidationDialogOpen(false)
                  setValidationResult(null)
                  setValidationPackSlug(null)
                  if (result.warnings && result.warnings.length > 0) {
                    toast.warning(
                      `Imported with ${result.warnings.length} warning(s)`,
                      { description: result.warnings[0] }
                    )
                  } else {
                    toast.success(`Successfully imported ${result.packName}`)
                  }
                } catch {
                  toast.error('Import failed')
                }
              }
            : undefined
        }
        isImporting={importMutation.isPending}
      />
    </div>
  )
}
