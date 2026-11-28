import { useState, useMemo } from 'react'
import {
  Download,
  Loader2,
  CheckCircle2,
  AlertCircle,
  CircleDashed,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { usePackOverlays } from '@/features/libraries/api/packs'
import type { UnifiedPack } from './unified-pack'
import {
  collectPacksToImport,
  importButtonLabel,
  packContentsSummary,
  packSourceUrl,
  serverErrorMessage,
  type CatalogSourceInfo,
} from './pack-list-helpers'

export function ImportPackDialog({
  pack,
  allPacks,
  catalogSource = null,
  open,
  onOpenChange,
  onConfirm,
}: {
  pack: UnifiedPack | null
  /** Every pack on the page, to walk the whole dependency chain. */
  allPacks: UnifiedPack[]
  /** Names where a catalog pack is downloaded from. */
  catalogSource?: CatalogSourceInfo | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (pack: UnifiedPack, selectedOverlays: string[] | null) => void
}) {
  const {
    data: overlaysData,
    isLoading: loadingOverlays,
    error: overlaysError,
  } = usePackOverlays(pack?.relativePath || null)
  // Every overlay is ticked unless the user unticks it, including those for a
  // framework that is not imported yet: that mapping is saved and added when
  // the framework is imported. The parent gives this dialog a key per pack, so
  // the unticked set starts empty for each pack.
  const [uncheckedOverlays, setUncheckedOverlays] = useState<Set<string>>(new Set())

  const { packs: packsToImport, unavailableDependencies } = useMemo(
    () => (pack ? collectPacksToImport(pack, allPacks) : { packs: [], unavailableDependencies: [] }),
    [pack, allPacks],
  )
  const importedDirectDependencies = useMemo(
    () => (pack?.dependsOn ?? []).filter((dependency) => dependency.isImported),
    [pack],
  )

  const toggleOverlay = (frameworkId: string) => {
    setUncheckedOverlays((previous) => {
      const next = new Set(previous)
      if (next.has(frameworkId)) {
        next.delete(frameworkId)
      } else {
        next.add(frameworkId)
      }
      return next
    })
  }

  const handleImport = () => {
    if (!pack) return
    // If there are no overlays, pass null to load all (default behavior)
    // If there are overlays, pass the selected list
    const overlays =
      (overlaysData?.overlays.length ?? 0) > 0
        ? overlaysData!.overlays
            .map((overlay) => overlay.frameworkId)
            .filter((frameworkId) => !uncheckedOverlays.has(frameworkId))
        : null
    onConfirm(pack, overlays)
  }

  const hasOverlays = (overlaysData?.overlays.length ?? 0) > 0
  const isCatalogPack = pack?.source === 'catalog'
  const overlaysFailed = overlaysError !== null && overlaysError !== undefined
  const hasDependencySection =
    packsToImport.length > 0 || importedDirectDependencies.length > 0 || unavailableDependencies.length > 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>
            {pack?.isInDatabase ? `Install ${pack.name} ${pack.version}` : `Import ${pack?.name}`}
          </DialogTitle>
          <DialogDescription>
            {hasOverlays
              ? 'Select which compliance framework overlays to include with this pack.'
              : `Import ${pack?.name} to make its content available.`}
          </DialogDescription>
        </DialogHeader>

        {pack && (
          <p className="text-sm text-muted-foreground" data-testid="pack-contents-summary">
            {packContentsSummary(pack)}
          </p>
        )}
        {pack?.source === 'catalog' && catalogSource && (
          <p className="text-xs text-muted-foreground" data-testid="pack-download-source">
            Downloaded from{' '}
            {packSourceUrl(catalogSource, pack.relativePath) ? (
              <a
                href={packSourceUrl(catalogSource, pack.relativePath)}
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-2"
              >
                {catalogSource.name}
              </a>
            ) : (
              catalogSource.name
            )}
            , release {catalogSource.release}.
          </p>
        )}

        {hasDependencySection && (
          <div className="space-y-2 py-2" data-testid="import-dependencies">
            <p className="text-sm font-medium">Dependencies</p>
            <div className="space-y-1.5">
              {importedDirectDependencies.map((dependency) => (
                <div key={dependency.slug} className="flex items-center gap-2 text-sm">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  <span>{dependency.name}</span>
                </div>
              ))}
              {packsToImport.map((dependencyPack) => (
                <div key={dependencyPack.slug} className="flex items-center gap-2 text-sm">
                  <CircleDashed className="h-4 w-4 text-blue-600" />
                  <span>{dependencyPack.name}</span>
                  <span className="text-xs text-blue-700">will be imported</span>
                </div>
              ))}
              {unavailableDependencies.map((dependencySlug) => (
                <div key={dependencySlug} className="flex items-center gap-2 text-sm">
                  <AlertCircle className="h-4 w-4 text-amber-600" />
                  <span>{dependencySlug}</span>
                  <span className="text-xs text-amber-600">not available</span>
                </div>
              ))}
            </div>
            {packsToImport.length > 0 && (
              <p className="text-xs text-muted-foreground">Missing dependencies are imported first.</p>
            )}
          </div>
        )}

        {loadingOverlays ? (
          <div className="py-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            {isCatalogPack && <span>Downloading pack...</span>}
          </div>
        ) : overlaysFailed ? (
          <p className="py-2 text-sm text-red-700" data-testid="overlays-error">
            {serverErrorMessage(overlaysError) ?? 'The pack could not be loaded.'}
          </p>
        ) : hasOverlays ? (
          <div className="space-y-2 py-2">
            <p className="text-sm font-medium">
              Compliance mappings: <span className="font-normal text-muted-foreground">uncheck to unmap</span>
            </p>
            {overlaysData?.overlays.some((overlay) => !overlay.frameworkExists) && (
              <p className="text-xs text-amber-600">
                Mappings to a framework you have not imported are saved. They show up in your threat models
                when you import that framework.
              </p>
            )}
            <div className="space-y-3">
              {overlaysData?.overlays.map((overlay) => (
                <div key={overlay.frameworkId} className="flex items-start gap-3">
                  <Checkbox
                    id={overlay.frameworkId}
                    checked={!uncheckedOverlays.has(overlay.frameworkId)}
                    onCheckedChange={() => toggleOverlay(overlay.frameworkId)}
                  />
                  <div className="flex-1">
                    <Label htmlFor={overlay.frameworkId}>{overlay.frameworkName}</Label>
                    <p className="text-xs text-muted-foreground">
                      {overlay.mappingCount} mappings
                      {!overlay.frameworkExists && (
                        <span className="block text-amber-600">
                          Saved. Import the pack that provides {overlay.frameworkId} to see them.
                        </span>
                      )}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <p className="text-xs text-muted-foreground">Imported packs are connected to every threat model.</p>
        {pack?.isInDatabase && pack.databaseVersion && (
          <p className="text-xs text-muted-foreground" data-testid="installed-version">
            Installed version: {pack.databaseVersion}
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleImport} disabled={loadingOverlays || overlaysFailed}>
            <Download className="mr-2 h-4 w-4" />
            {pack ? importButtonLabel(pack, packsToImport.length + 1) : 'Import'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
