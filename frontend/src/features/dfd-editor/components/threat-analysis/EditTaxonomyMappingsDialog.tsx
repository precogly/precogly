import { useState, useMemo } from 'react'
import { Plus, Trash2, Tags, Search } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import {
  type TaxonomyEntry,
  formatTaxonomyEntryLabel,
  getTaxonomyEntryColor,
  getTaxonomyEntryBgClass,
} from '@/types/domain'
import { useTaxonomies, useTaxonomyEntries } from '@/features/libraries/api/libraries'
import {
  useInstanceTaxonomyEntries,
  useCreateInstanceTaxonomyEntry,
  useDeleteInstanceTaxonomyEntry,
} from '@/features/threat-models/api/threats'

interface EditTaxonomyMappingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatId: number
  threatName: string
  libraryTaxonomyEntries: TaxonomyEntry[]
}

function TaxonomyBadgeInline({ entry }: { entry: TaxonomyEntry }) {
  const label = formatTaxonomyEntryLabel(entry)
  const bgClass = getTaxonomyEntryBgClass(entry)
  const color = getTaxonomyEntryColor(entry)

  if (bgClass) {
    return (
      <Badge variant="outline" className={`text-xs shrink-0 ${bgClass}`}>
        {label}
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className="text-xs shrink-0" style={{ borderColor: color, color }}>
      {label}
    </Badge>
  )
}

export function EditTaxonomyMappingsDialog({
  open,
  onOpenChange,
  threatId,
  threatName,
  libraryTaxonomyEntries,
}: EditTaxonomyMappingsDialogProps) {
  const [selectedTaxonomySlug, setSelectedTaxonomySlug] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')

  const { data: taxonomies, isLoading: taxonomiesLoading } = useTaxonomies()
  const { data: allEntries, isLoading: entriesLoading } = useTaxonomyEntries()
  const { data: instanceEntries, isLoading: instanceLoading } =
    useInstanceTaxonomyEntries(threatId)

  const createEntry = useCreateInstanceTaxonomyEntry()
  const deleteEntry = useDeleteInstanceTaxonomyEntry()

  const mergedEntries = useMemo(() => {
    const entries: Array<{
      instanceLinkId?: number
      taxonomyEntryId?: number
      taxonomySlug: string
      taxonomyName: string
      externalId: string
      title: string
      referenceUrl: string
      source: 'library' | 'instance'
    }> = []
    const seen = new Set<string>()

    libraryTaxonomyEntries.forEach((e) => {
      const key = `${e.taxonomySlug}:${e.externalId}`
      if (!seen.has(key)) {
        seen.add(key)
        entries.push({
          taxonomyEntryId: e.id,
          taxonomySlug: e.taxonomySlug,
          taxonomyName: e.taxonomyName ?? e.taxonomySlug,
          externalId: e.externalId,
          title: e.title,
          referenceUrl: e.referenceUrl ?? '',
          source: 'library',
        })
      }
    })

    instanceEntries?.forEach((ie) => {
      const key = `${ie.taxonomySlug}:${ie.externalId}`
      if (!seen.has(key)) {
        seen.add(key)
        entries.push({
          instanceLinkId: ie.id,
          taxonomyEntryId: ie.taxonomyEntry,
          taxonomySlug: ie.taxonomySlug,
          taxonomyName: ie.taxonomyName,
          externalId: ie.externalId,
          title: ie.title,
          referenceUrl: ie.referenceUrl,
          source: 'instance',
        })
      }
    })

    return entries
  }, [libraryTaxonomyEntries, instanceEntries])

  const mappedEntryIds = useMemo(() => {
    const ids = new Set<number>()
    mergedEntries.forEach((e) => {
      if (e.taxonomyEntryId) ids.add(e.taxonomyEntryId)
    })
    return ids
  }, [mergedEntries])

  const availableEntries = useMemo(() => {
    if (!allEntries || !selectedTaxonomySlug) return []
    return allEntries.filter((e) => {
      if (e.taxonomySlug !== selectedTaxonomySlug) return false
      if (e.id && mappedEntryIds.has(e.id)) return false
      if (searchQuery) {
        const query = searchQuery.toLowerCase()
        return (
          e.externalId.toLowerCase().includes(query) ||
          e.title.toLowerCase().includes(query)
        )
      }
      return true
    })
  }, [allEntries, selectedTaxonomySlug, mappedEntryIds, searchQuery])

  const handleAddEntry = (taxonomyEntryId: number) => {
    createEntry.mutate({ taxonomyEntry: taxonomyEntryId, threat: threatId })
  }

  const handleDeleteEntry = (instanceLinkId: number) => {
    deleteEntry.mutate(instanceLinkId)
  }

  const isLoading = taxonomiesLoading || entriesLoading || instanceLoading

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Tags className="h-5 w-5" />
            Edit Taxonomy Entries
          </DialogTitle>
          <DialogDescription>
            Manage taxonomy classifications for:{' '}
            <span className="font-medium">{threatName}</span>
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-8 text-center text-muted-foreground">Loading...</div>
        ) : (
          <div className="space-y-4">
            {/* Current entries */}
            <div className="space-y-2">
              <Label>Current Taxonomy Entries</Label>
              <ScrollArea className="h-[200px] border rounded-md overflow-hidden">
                {mergedEntries.length === 0 ? (
                  <div className="p-4 text-center text-muted-foreground">
                    No taxonomy entries assigned
                  </div>
                ) : (
                  <div className="p-2 space-y-2 overflow-hidden">
                    {mergedEntries.map((entry) => (
                      <div
                        key={`${entry.taxonomySlug}-${entry.externalId}`}
                        className="flex items-center gap-2 p-2 rounded bg-muted/30 overflow-hidden"
                      >
                        <div className="flex items-center gap-2 min-w-0 flex-1 overflow-hidden">
                          <TaxonomyBadgeInline
                            entry={{
                              taxonomySlug: entry.taxonomySlug,
                              externalId: entry.externalId,
                              title: entry.title,
                            }}
                          />
                          <span className="text-sm text-muted-foreground truncate">
                            {entry.title}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {entry.source === 'library' ? (
                            <Badge variant="secondary" className="text-xs">
                              Library
                            </Badge>
                          ) : (
                            <>
                              <Badge variant="secondary" className="text-xs">
                                Custom
                              </Badge>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7 text-destructive hover:text-destructive"
                                onClick={() => handleDeleteEntry(entry.instanceLinkId!)}
                                disabled={deleteEntry.isPending}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </div>

            {/* Add new entry */}
            <div className="space-y-3 pt-3 border-t">
              <Label>Add New Entry</Label>

              <div className="space-y-2">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Taxonomy</Label>
                  <Select
                    value={selectedTaxonomySlug}
                    onValueChange={(v) => {
                      setSelectedTaxonomySlug(v)
                      setSearchQuery('')
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select taxonomy..." />
                    </SelectTrigger>
                    <SelectContent>
                      {taxonomies?.map((t) => (
                        <SelectItem key={t.slug} value={t.slug}>
                          {t.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {selectedTaxonomySlug && (
                  <>
                    <div className="relative">
                      <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search entries..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8"
                      />
                    </div>
                    <ScrollArea className="h-[150px] border rounded-md">
                      {availableEntries.length === 0 ? (
                        <div className="p-4 text-center text-muted-foreground text-sm">
                          {searchQuery
                            ? 'No matching entries found'
                            : 'All entries from this taxonomy are already assigned'}
                        </div>
                      ) : (
                        <div className="p-2 space-y-1">
                          {availableEntries.map((entry) => (
                            <div
                              key={entry.id}
                              className="flex items-center justify-between gap-2 p-2 rounded-md hover:bg-muted transition-colors"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <TaxonomyBadgeInline entry={entry} />
                                <span className="text-sm truncate">{entry.title}</span>
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs shrink-0"
                                onClick={() => handleAddEntry(entry.id!)}
                                disabled={createEntry.isPending}
                              >
                                <Plus className="h-3 w-3 mr-1" />
                                Add
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </ScrollArea>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
