/**
 * Dialog for previewing pack contents (components, threats, countermeasures).
 */

import { useState } from 'react'
import { Loader2, Package } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ScrollArea } from '@/components/ui/scroll-area'
import { serverErrorMessage } from './pack-list-helpers'
import {
  usePackPreview,
  useSourcePackPreview,
  type PackPreviewResponse,
} from '@/features/libraries/api/packs'

interface PreviewPackDialogProps {
  /** Pack ID for database packs */
  packId?: number | null
  /** Pack relative path for source packs */
  packPath?: string | null
  /** A catalog pack is downloaded to preview it; the loading text says so. */
  isCatalogPack?: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function PreviewPackDialog({
  packId,
  packPath,
  isCatalogPack = false,
  open,
  onOpenChange,
}: PreviewPackDialogProps) {
  // Use the appropriate hook based on what's provided
  const dbPreview = usePackPreview(packPath ? null : packId ?? null)
  const sourcePreview = useSourcePackPreview(packId ? null : packPath ?? null)

  const isLoading = packPath ? sourcePreview.isLoading : dbPreview.isLoading
  const preview = packPath ? sourcePreview.data : dbPreview.data
  const loadError = packPath ? sourcePreview.error : dbPreview.error

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
        {isLoading ? (
          <>
            <DialogHeader>
              <DialogTitle>Loading Pack Preview</DialogTitle>
              <DialogDescription>
                {isCatalogPack ? 'Downloading pack...' : 'Please wait while we load the pack details.'}
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          </>
        ) : preview ? (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Package className="h-5 w-5" />
                {preview.pack.name}
              </DialogTitle>
              <DialogDescription className="flex items-center gap-2 flex-wrap">
                <PackTypeBadge type={preview.pack.packType} />
                {preview.pack.author && (
                  <span className="text-xs">by {preview.pack.author}</span>
                )}
              </DialogDescription>
            </DialogHeader>

            {preview.pack.description && (
              <p className="text-sm text-muted-foreground">
                {preview.pack.description}
              </p>
            )}

            <PreviewTabs preview={preview} />
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Pack Preview</DialogTitle>
              <DialogDescription>Unable to load pack details.</DialogDescription>
            </DialogHeader>
            <div className="text-center py-12 text-muted-foreground">
              {serverErrorMessage(loadError) ?? 'Failed to load pack preview.'}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function PreviewTabs({ preview }: { preview: PackPreviewResponse }) {
  const componentCount = preview.components.length
  const threatCount = preview.threats.length
  const countermeasureCount = preview.countermeasures.length
  const requirementCount = preview.requirements?.length ?? 0
  const taxonomyEntryCount = preview.taxonomies?.reduce((sum, t) => sum + (t.entries?.length ?? 0), 0) ?? 0

  // Build list of available sections with counts
  const sections = [
    ...(taxonomyEntryCount > 0 ? [{ value: 'taxonomies', label: 'Taxonomy Entries', count: taxonomyEntryCount }] : []),
    { value: 'components', label: 'Components', count: componentCount },
    { value: 'threats', label: 'Threats', count: threatCount },
    { value: 'countermeasures', label: 'Countermeasures', count: countermeasureCount },
    { value: 'requirements', label: 'Requirements', count: requirementCount },
  ]

  // Default to first section with content, or first section overall
  const defaultSection = sections.find((s) => s.count > 0)?.value ?? sections[0].value
  const [activeSection, setActiveSection] = useState(defaultSection)

  return (
    <div className="flex-1 flex flex-col min-h-0 space-y-3">
      <Select value={activeSection} onValueChange={setActiveSection}>
        <SelectTrigger className="w-[240px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {sections.map((section) => (
            <SelectItem key={section.value} value={section.value}>
              {section.label} ({section.count})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <ScrollArea className="h-[350px]">
        {activeSection === 'taxonomies' && taxonomyEntryCount > 0 && (
          <div className="space-y-2 pr-4">
            {preview.taxonomies.flatMap((taxonomy) =>
              taxonomy.entries.map((entry, idx) => (
                <div
                  key={`${taxonomy.slug}-${entry.externalId || idx}`}
                  className="border rounded-lg p-3 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{entry.title}</span>
                    <div className="flex gap-1">
                      {entry.externalId && (
                        <Badge variant="outline" className="text-xs">
                          {entry.externalId}
                        </Badge>
                      )}
                      <Badge variant="secondary" className="text-xs">
                        {taxonomy.name}
                      </Badge>
                    </div>
                  </div>
                  {entry.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {entry.description}
                    </p>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeSection === 'components' && (
          componentCount === 0 ? (
            <EmptyState text="No components in this pack" />
          ) : (
            <div className="space-y-2 pr-4">
              {preview.components.map((comp, idx) => (
                <div
                  key={comp.slug || idx}
                  className="border rounded-lg p-3 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{comp.name}</span>
                    <div className="flex gap-1">
                      {comp.category && (
                        <Badge variant="secondary" className="text-xs">
                          {comp.category}
                        </Badge>
                      )}
                      {comp.componentType && (
                        <Badge variant="outline" className="text-xs">
                          {comp.componentType}
                        </Badge>
                      )}
                    </div>
                  </div>
                  {comp.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {comp.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )
        )}

        {activeSection === 'threats' && (
          threatCount === 0 ? (
            <EmptyState text="No threats in this pack" />
          ) : (
            <div className="space-y-2 pr-4">
              {preview.threats.map((threat, idx) => (
                <div
                  key={threat.slug || idx}
                  className="border rounded-lg p-3 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{threat.name}</span>
                    <div className="flex gap-1">
                      <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={3} size="sm" />
                      {threat.severity && (
                        <SeverityBadge severity={threat.severity} />
                      )}
                    </div>
                  </div>
                  {threat.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {threat.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )
        )}

        {activeSection === 'countermeasures' && (
          countermeasureCount === 0 ? (
            <EmptyState text="No countermeasures in this pack" />
          ) : (
            <div className="space-y-2 pr-4">
              {preview.countermeasures.map((cm, idx) => (
                <div
                  key={cm.slug || idx}
                  className="border rounded-lg p-3 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{cm.name}</span>
                    <div className="flex gap-1">
                      {cm.defaultStatus === 'platform' && (
                        <Badge variant="secondary" className="bg-blue-100 text-blue-800 text-xs">
                          Platform
                        </Badge>
                      )}
                      {cm.controlFunctions?.map((fn) => (
                        <Badge key={fn} variant="secondary" className="text-xs capitalize">
                          {fn}
                        </Badge>
                      ))}
                      {cm.cost && <CostBadge cost={cm.cost} />}
                    </div>
                  </div>
                  {cm.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {cm.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )
        )}

        {activeSection === 'requirements' && (
          requirementCount === 0 ? (
            <EmptyState text="No requirements in this pack" />
          ) : (
            <div className="space-y-2 pr-4">
              {preview.requirements.map((req, idx) => (
                <div
                  key={req.sectionCode || idx}
                  className="border rounded-lg p-3 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{req.sectionCode}</span>
                    {req.frameworkName && (
                      <Badge variant="outline" className="text-xs">
                        {req.frameworkName}
                      </Badge>
                    )}
                  </div>
                  {req.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {req.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )
        )}
      </ScrollArea>
    </div>
  )
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
      {text}
    </div>
  )
}

function PackTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    technology: 'bg-blue-100 text-blue-800',
    threat: 'bg-red-100 text-red-800',
    countermeasure: 'bg-green-100 text-green-800',
    compliance: 'bg-purple-100 text-purple-800',
    template: 'bg-yellow-100 text-yellow-800',
    full: 'bg-gray-100 text-gray-800',
    taxonomy: 'bg-teal-100 text-teal-800',
  }
  return (
    <Badge variant="secondary" className={colors[type] || ''}>
      {type}
    </Badge>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-red-100 text-red-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
  }
  return (
    <Badge variant="secondary" className={colors[severity] || ''}>
      {severity}
    </Badge>
  )
}

function CostBadge({ cost }: { cost: string }) {
  const colors: Record<string, string> = {
    low: 'bg-green-100 text-green-800',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-red-100 text-red-800',
  }
  return (
    <Badge variant="outline" className={colors[cost] || ''}>
      {cost} cost
    </Badge>
  )
}
