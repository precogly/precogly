/**
 * Pick a threat's categories (taxonomy entries): the model's methodologies as
 * one-click chips (STRIDE's six categories by default), and every installed
 * taxonomy behind a search box, grouped by taxonomy. Several can be picked.
 *
 * Fixed categories are shown with a lock and are not edited here: the library
 * threat's own, and snapshot ones kept from a library that is not installed.
 */
import { useMemo, useState } from 'react'
import { Check, Lock, Plus, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'
import { DEFAULT_METHODOLOGIES, type TaxonomyEntry } from '@/types/domain'
import { useTaxonomyEntries } from '@/features/libraries/api/libraries'
import { useThreatModel } from '@/features/threat-models/api/threat-models'
import {
  chipGroups,
  fixedEntryHint,
  groupTaxonomyEntries,
  methodologyTaxonomySlugs,
  orderedSearchGroups,
  taxonomyEntryKey,
  taxonomyEntryLabel,
  taxonomyEntrySearchText,
  toggleEntryId,
} from './taxonomy-picker-utils'

interface TaxonomyCategoryPickerProps {
  threatModelId: string
  /** Selected taxonomy entry ids. */
  value: number[]
  onChange: (entryIds: number[]) => void
  /** Categories the library threat brings, and snapshot ones; shown, not editable. */
  lockedEntries?: TaxonomyEntry[]
  disabled?: boolean
  className?: string
}

export function TaxonomyCategoryPicker({
  threatModelId,
  value,
  onChange,
  lockedEntries = [],
  disabled = false,
  className,
}: TaxonomyCategoryPickerProps) {
  const [searchOpen, setSearchOpen] = useState(false)
  const { data: allEntries = [] } = useTaxonomyEntries()
  const { data: threatModel } = useThreatModel(threatModelId)
  const methodologies = threatModel?.methodologies ?? DEFAULT_METHODOLOGIES

  const groups = useMemo(() => groupTaxonomyEntries(allEntries), [allEntries])
  const quickSlugs = useMemo(() => methodologyTaxonomySlugs(methodologies, groups), [methodologies, groups])
  const chips = useMemo(() => chipGroups(groups, quickSlugs), [groups, quickSlugs])
  const searchGroups = useMemo(() => orderedSearchGroups(groups, quickSlugs), [groups, quickSlugs])

  const lockedIds = useMemo(
    () => new Set(lockedEntries.map((entry) => entry.id).filter((id): id is number => id !== undefined)),
    [lockedEntries]
  )
  // Snapshot entries have no id, so fixed entries are also matched by taxonomy and external id.
  const lockedKeys = useMemo(() => new Set(lockedEntries.map(taxonomyEntryKey)), [lockedEntries])
  const isLocked = (entry: TaxonomyEntry) =>
    (entry.id !== undefined && lockedIds.has(entry.id)) || lockedKeys.has(taxonomyEntryKey(entry))
  const chipEntryIds = useMemo(
    () => new Set(chips.flatMap((group) => group.entries.map((entry) => entry.id))),
    [chips]
  )
  const chipKeys = useMemo(
    () => new Set(chips.flatMap((group) => group.entries.map(taxonomyEntryKey))),
    [chips]
  )
  const entriesById = useMemo(() => new Map(allEntries.map((entry) => [entry.id, entry])), [allEntries])
  // Picked entries that have no chip: listed as removable badges.
  const otherSelected = value
    .filter((entryId) => !chipEntryIds.has(entryId))
    .map((entryId) => entriesById.get(entryId))
    .filter((entry): entry is TaxonomyEntry => !!entry)
  // Fixed categories with no chip: listed as fixed badges.
  const otherLocked = lockedEntries.filter((entry) => !chipKeys.has(taxonomyEntryKey(entry)))

  const toggle = (entry: TaxonomyEntry) => {
    if (disabled || entry.id === undefined || isLocked(entry)) return
    onChange(toggleEntryId(value, entry.id))
  }

  return (
    <div className={cn('space-y-2', className)}>
      {chips.map((group) => (
        <div key={group.slug} className="space-y-1">
          <p className="text-xs text-muted-foreground">{group.name}</p>
          <div className="flex flex-wrap gap-1">
            {group.entries.map((entry) => {
              const locked = isLocked(entry)
              const selected = locked || (entry.id !== undefined && value.includes(entry.id))
              return (
                <Button
                  key={entry.id ?? entry.externalId}
                  type="button"
                  size="sm"
                  variant={selected ? 'default' : 'outline'}
                  className="h-7 gap-1 px-2 text-xs"
                  disabled={disabled || locked}
                  aria-pressed={selected}
                  title={locked ? fixedEntryHint(entry) : entry.title}
                  onClick={() => toggle(entry)}
                >
                  {locked && <Lock className="h-3 w-3" />}
                  {taxonomyEntryLabel(entry)}
                </Button>
              )
            })}
          </div>
        </div>
      ))}

      {(otherSelected.length > 0 || otherLocked.length > 0) && (
        <div className="flex flex-wrap gap-1">
          {otherLocked.map((entry) => (
            <Badge
              key={`locked-${taxonomyEntryKey(entry)}`}
              variant="secondary"
              className="gap-1 text-xs font-normal"
              title={fixedEntryHint(entry)}
            >
              <Lock className="h-3 w-3" />
              {taxonomyEntryLabel(entry)}
            </Badge>
          ))}
          {otherSelected.map((entry) => (
            <Badge key={entry.id} variant="outline" className="gap-1 text-xs font-normal">
              {taxonomyEntryLabel(entry)}
              <button
                type="button"
                className="rounded-sm hover:text-destructive disabled:opacity-50"
                aria-label={`Remove ${taxonomyEntryLabel(entry)}`}
                disabled={disabled}
                onClick={() => toggle(entry)}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}

      <Popover open={searchOpen} onOpenChange={setSearchOpen} modal>
        <PopoverTrigger asChild>
          <Button type="button" variant="outline" size="sm" className="h-7 gap-1 text-xs" disabled={disabled}>
            <Plus className="h-3 w-3" />
            {chips.length > 0 ? 'More categories' : 'Add category'}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[420px] p-0" align="start">
          <Command>
            <CommandInput placeholder="Search by id or name, such as T1005 or phishing" />
            <CommandList className="max-h-72">
              <CommandEmpty>No category matches.</CommandEmpty>
              {searchGroups.map((group) => (
                <CommandGroup key={group.slug} heading={group.name}>
                  {group.entries.map((entry) => {
                    const locked = isLocked(entry)
                    const selected = locked || (entry.id !== undefined && value.includes(entry.id))
                    return (
                      <CommandItem
                        key={entry.id ?? entry.externalId}
                        // cmdk matches on the value; the id keeps equal titles apart.
                        value={`${taxonomyEntrySearchText(entry)} #${entry.id}`}
                        disabled={locked}
                        onSelect={() => toggle(entry)}
                        className="text-xs"
                      >
                        <Check className={cn('mr-2 h-3 w-3', selected ? 'opacity-100' : 'opacity-0')} />
                        <span className="truncate">{taxonomyEntryLabel(entry)}</span>
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              ))}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  )
}
