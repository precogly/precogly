import {
  Package,
  Loader2,
  ChevronDown,
  ChevronRight,
  Trash2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PackContents } from './PackContents'
import { packTypeColors } from '../constants'
import type { WaitingFramework } from '../types/packs'

export function ImportedPackRow({
  pack,
  isExpanded,
  onToggleExpand,
  onUnimport,
  isUnimporting,
  isSecurityTeam,
}: {
  pack: {
    id: number
    slug: string
    name: string
    version: string
    packType: string
    description: string
    waitingFrameworks?: WaitingFramework[]
  }
  isExpanded: boolean
  onToggleExpand: () => void
  onUnimport: () => void
  isUnimporting: boolean
  isSecurityTeam: boolean
}) {
  const handleUnimportClick = (e: React.MouseEvent) => {
    e.stopPropagation() // Prevent row expansion
    onUnimport()
  }

  return (
    <div className="border rounded-lg">
      {/* Header Row */}
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/50 transition-colors"
        onClick={onToggleExpand}
      >
        <div className="flex items-center gap-3">
          {isExpanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
          <div className="p-2 bg-muted rounded-lg">
            <Package className="h-5 w-5 text-muted-foreground" />
          </div>
          <div>
            <h3 className="font-semibold">{pack.name}</h3>
            {pack.waitingFrameworks && pack.waitingFrameworks.length > 0 && (
              <p className="text-xs text-amber-700" data-testid="waiting-frameworks">
                Mappings waiting for a framework:{' '}
                {pack.waitingFrameworks
                  .map((waiting) => `${waiting.frameworkSlug} (${waiting.mappingCount})`)
                  .join(', ')}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant="secondary"
            className={packTypeColors[pack.packType] || 'bg-gray-100'}
          >
            {pack.packType}
          </Badge>
          {isSecurityTeam && (
            <Button
              size="sm"
              variant="outline"
              onClick={handleUnimportClick}
              disabled={isUnimporting}
              className="text-destructive hover:text-destructive hover:bg-destructive/10"
              title="Unimport this pack"
            >
              {isUnimporting ? (
                <Loader2 className="h-3 w-3 animate-spin mr-1" />
              ) : (
                <Trash2 className="h-3 w-3 mr-1" />
              )}
              Unimport
            </Button>
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="border-t px-4 py-3 bg-muted/30">
          <PackContents packId={pack.id} />
        </div>
      )}
    </div>
  )
}
