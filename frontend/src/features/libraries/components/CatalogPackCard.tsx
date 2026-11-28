import {
  Package,
  Loader2,
  Eye,
  Check,
  Download,
  ShieldCheck,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { UnifiedPack } from './unified-pack'
import { packTypeColors } from '../constants'
import { packCategoryFromPath, type CatalogSourceInfo } from './pack-list-helpers'
import { PackBadge } from './PackBadge'

export function CatalogPackCard({
  pack,
  onImport,
  onPreview,
  onValidate,
  isImporting,
  isValidating,
  isSecurityTeam,
  fullVersionPack = null,
  onShowFullVersion,
  catalogSource = null,
}: {
  pack: UnifiedPack
  onImport: (pack: UnifiedPack) => void
  onPreview: (pack: UnifiedPack) => void
  onValidate?: (pack: UnifiedPack) => void
  isImporting: boolean
  isValidating?: boolean
  isSecurityTeam: boolean
  /** For a demo pack: its full version, when the list offers it. */
  fullVersionPack?: UnifiedPack | null
  onShowFullVersion?: (fullPack: UnifiedPack) => void
  /** Names the source in the Library repo badge's tooltip. */
  catalogSource?: CatalogSourceInfo | null
}) {
  const { isDemo } = packCategoryFromPath(pack.relativePath)
  // Imported earlier, but no copy of its files is offered any more.
  const sourceUnavailable = pack.isInDatabase && !pack.relativePath
  // The versions differ; which one is newer is for the user to judge, since a
  // pinned older catalog can offer a lower version than the installed one.
  const updateAvailable = pack.isImported && pack.needsUpdate
  return (
    <div className="border rounded-lg p-4 space-y-3 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-muted rounded-lg">
            <Package className="h-5 w-5 text-muted-foreground" />
          </div>
          <div>
            <h3 className="font-semibold">{pack.name}</h3>
            <div className="flex items-center gap-1">
              <Badge
                variant="secondary"
                className={`text-xs ${packTypeColors[pack.packType] || 'bg-gray-100'}`}
              >
                {pack.packType}
              </Badge>
              {isDemo && (
                <Badge variant="outline" className="text-xs" data-testid="demo-pack-badge">
                  Demo
                </Badge>
              )}
              {pack.source && (
                <span
                  data-testid="pack-source-badge"
                  title={
                    pack.source === 'catalog' && catalogSource
                      ? `From ${catalogSource.name}, release ${catalogSource.release}`
                      : pack.source === 'bundled'
                        ? 'Bundled with this Precogly server'
                        : undefined
                  }
                >
                  <PackBadge packName={pack.source === 'catalog' ? 'Library repo' : 'Bundled'} />
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      <p className="text-sm text-muted-foreground line-clamp-3">
        {pack.description || 'No description available'}
      </p>

      {sourceUnavailable && (
        <p className="text-xs text-muted-foreground" data-testid="source-not-available">
          Source not available. The pack's data stays in use; its files are not on this server.
        </p>
      )}

      {updateAvailable && (
        <p className="text-xs text-amber-700" data-testid="pack-versions">
          Installed {pack.databaseVersion}, library has {pack.version}
        </p>
      )}

      {fullVersionPack && onShowFullVersion && (
        <p className="text-xs">
          <button
            type="button"
            className="text-primary underline-offset-2 hover:underline"
            onClick={() => onShowFullVersion(fullVersionPack)}
            data-testid="full-version-link"
          >
            Full version: {fullVersionPack.name}
          </button>
        </p>
      )}

      {pack.dependsOn.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Depends on: {pack.dependsOn.map((d) => d.name).join(', ')}
        </p>
      )}

      <div className="flex items-center justify-between pt-2 border-t">
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => onPreview(pack)}
            title="Preview pack contents"
          >
            <Eye className="h-4 w-4 mr-1" />
            Preview
          </Button>
          {isSecurityTeam && onValidate && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onValidate(pack)}
              disabled={isValidating}
              title="Validate pack references"
            >
              {isValidating ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <ShieldCheck className="h-4 w-4 mr-1" />
              )}
              Validate
            </Button>
          )}
        </div>
        <div className="flex items-center gap-2">
          {pack.isImported ? (
            <>
              {updateAvailable && (
                <Badge variant="outline" className="text-amber-700 border-amber-600" data-testid="update-available-badge">
                  Update available
                </Badge>
              )}
              <Badge variant="outline" className="text-green-600 border-green-600">
                <Check className="mr-1 h-3 w-3" />
                Imported
              </Badge>
              {updateAvailable && isSecurityTeam && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onImport(pack)}
                  disabled={isImporting}
                  data-testid="install-version-button"
                >
                  {isImporting ? (
                    <Loader2 className="mr-2 h-3 w-3 animate-spin" />
                  ) : (
                    <Download className="mr-2 h-3 w-3" />
                  )}
                  Install {pack.version}
                </Button>
              )}
            </>
          ) : isSecurityTeam ? (
            <Button size="sm" onClick={() => onImport(pack)} disabled={isImporting}>
              {isImporting ? (
                <Loader2 className="mr-2 h-3 w-3 animate-spin" />
              ) : (
                <Download className="mr-2 h-3 w-3" />
              )}
              Import
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
