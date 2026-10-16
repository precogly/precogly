/**
 * The risk tab's threat picker (plan 11.4): one list of the model's active
 * threats, each shown as `T7 Name (target, target)`. The caller owns the
 * selection and decides what a toggle does (local state in the add dialog,
 * the add and remove actions on an existing risk).
 */

import { useMemo, useState } from 'react'
import { ChevronRight, Loader2, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { threatPickerLabel, threatPickerMatches, type ThreatPickerEntry } from './risk-utils'

export interface ThreatPickerProps {
  entries: ThreatPickerEntry[]
  selectedThreatIds: number[]
  /** Called with the threat and whether it is now meant to be selected. */
  onToggle: (threatId: number, nextSelected: boolean) => void
  /** Shown on the trigger when nothing is selected. */
  triggerLabel?: string
  /** Disable the checkboxes while a link or unlink is in flight. */
  busy?: boolean
}

export function ThreatPicker({
  entries,
  selectedThreatIds,
  onToggle,
  triggerLabel = 'Select threats...',
  busy = false,
}: ThreatPickerProps) {
  const [pickerOpen, setPickerOpen] = useState(false)
  const [filter, setFilter] = useState('')

  const selectedCount = selectedThreatIds.length
  const filteredEntries = useMemo(
    () => entries.filter((entry) => threatPickerMatches(entry, filter)),
    [entries, filter]
  )

  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground py-2">No threats available to link.</p>
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        className="w-full justify-between"
        onClick={() => setPickerOpen(true)}
      >
        <span>
          {selectedCount > 0
            ? `${selectedCount} threat${selectedCount === 1 ? '' : 's'} linked`
            : triggerLabel}
        </span>
        <ChevronRight className="h-4 w-4" />
      </Button>
      <Dialog
        open={pickerOpen}
        onOpenChange={(open) => {
          setPickerOpen(open)
          if (!open) setFilter('')
        }}
      >
        <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Link threats</DialogTitle>
            <DialogDescription>
              Tick the threats this risk covers. {selectedCount > 0 && `${selectedCount} linked.`}
            </DialogDescription>
          </DialogHeader>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Filter by number, name or target"
              className="h-8 pl-7 text-sm"
              aria-label="Filter threats"
            />
          </div>
          <div className="flex-1 overflow-y-auto border rounded-md min-h-0" data-testid="threat-picker-list">
            {filteredEntries.length === 0 ? (
              <p className="text-sm text-muted-foreground px-3 py-2">No matching threats.</p>
            ) : (
              filteredEntries.map((entry) => {
                const isSelected = selectedThreatIds.includes(entry.threatId)
                return (
                  <label
                    key={entry.threatId}
                    className="flex items-center gap-2 px-3 py-2 hover:bg-muted/50 cursor-pointer border-b last:border-b-0"
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      disabled={busy}
                      onChange={() => onToggle(entry.threatId, !isSelected)}
                      className="rounded"
                    />
                    <span className="text-sm truncate flex-1 min-w-0">
                      <span className="font-mono text-xs text-muted-foreground mr-1">{entry.displayNumber}</span>
                      {threatPickerLabel(entry).slice(entry.displayNumber.length + 1)}
                    </span>
                  </label>
                )
              })
            )}
          </div>
          <DialogFooter>
            {busy && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground mr-auto" />}
            <Button variant="outline" onClick={() => setPickerOpen(false)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
