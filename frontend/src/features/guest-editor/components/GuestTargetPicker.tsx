import { useMemo } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { GuestTargetRef } from '../types'
import { targetOptions, type TargetOption } from '../lib/guest-targets'

interface GuestTargetPickerProps {
  nodes: readonly DiagramNode[]
  edges: readonly DiagramEdge[]
  selected: GuestTargetRef[]
  onChange: (targets: GuestTargetRef[]) => void
  /** When given, the picker offers "Whole system" and disables the list while it is on. */
  wholeSystem?: boolean
  onWholeSystemChange?: (wholeSystem: boolean) => void
  wholeSystemLabel?: string
  /** A note about targets the file names that are not on this diagram. */
  hiddenNote?: string | null
  idPrefix?: string
}

/**
 * The multi-target picker shared by the threat and countermeasure dialogs
 * (plan 11.9): components, flows, zones and boundaries, plus whole system.
 */
export function GuestTargetPicker({
  nodes,
  edges,
  selected,
  onChange,
  wholeSystem,
  onWholeSystemChange,
  wholeSystemLabel = 'Whole system',
  hiddenNote,
  idPrefix = 'target',
}: GuestTargetPickerProps) {
  const options = useMemo(() => targetOptions(nodes, edges), [nodes, edges])
  const selectedIds = new Set(selected.map((target) => target.id))
  const groups = useMemo(() => {
    const byGroup = new Map<string, TargetOption[]>()
    for (const option of options) {
      const list = byGroup.get(option.group) ?? []
      list.push(option)
      byGroup.set(option.group, list)
    }
    return [...byGroup.entries()]
  }, [options])

  const toggle = (option: TargetOption) => {
    if (selectedIds.has(option.ref.id)) {
      onChange(selected.filter((target) => target.id !== option.ref.id))
    } else {
      onChange([...selected, option.ref])
    }
  }

  return (
    <div className="space-y-2" data-testid={`${idPrefix}-picker`}>
      {onWholeSystemChange && (
        <label className="flex items-center gap-2 text-sm">
          <Switch
            id={`${idPrefix}-whole-system`}
            checked={wholeSystem === true}
            onCheckedChange={(checked) => onWholeSystemChange(checked === true)}
          />
          <span>{wholeSystemLabel}</span>
        </label>
      )}
      <div className={`rounded-md border p-2 max-h-48 overflow-y-auto space-y-2 ${wholeSystem ? 'opacity-50 pointer-events-none' : ''}`}>
        {groups.length === 0 && (
          <p className="text-xs text-muted-foreground px-1 py-2">No elements on the diagram yet.</p>
        )}
        {groups.map(([group, items]) => (
          <div key={group}>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider px-1">{group}</p>
            <div className="space-y-1 mt-1">
              {items.map((option) => {
                const Icon = option.icon
                const inputId = `${idPrefix}-${option.ref.type}-${option.ref.id}`
                return (
                  <div key={option.ref.id} className="flex items-center gap-2 px-1">
                    <Checkbox
                      id={inputId}
                      checked={selectedIds.has(option.ref.id)}
                      onCheckedChange={() => toggle(option)}
                      disabled={wholeSystem === true}
                    />
                    <Label htmlFor={inputId} className="flex items-center gap-1.5 text-sm font-normal cursor-pointer truncate">
                      <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      <span className="truncate">{option.label}</span>
                    </Label>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
      {hiddenNote && <p className="text-xs text-muted-foreground">{hiddenNote}</p>}
    </div>
  )
}
