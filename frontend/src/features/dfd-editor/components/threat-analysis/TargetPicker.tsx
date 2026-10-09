/**
 * A multi-target picker over the model's components, flows, zones and
 * boundaries (plan 11.3 dialogs), with an optional "whole system" choice.
 * Threats and countermeasures both use it: a threat with no targets must be
 * whole-system (I8); a countermeasure with no targets applies to the whole
 * system by definition (section 4.3).
 */

import { useMemo } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { MultiSelectCombobox, type ComboboxOption } from '@/components/ui/multi-select-combobox'
import { cn } from '@/lib/utils'
import type { TargetRef } from '@/features/threat-models/api/threats'
import { targetKey } from './analysis-selection'
import { useModelTargets } from './useModelTargets'

interface TargetPickerProps {
  threatModelId: string
  value: TargetRef[]
  onChange: (targets: TargetRef[]) => void
  /** Show the whole-system choice; it clears the targets when picked. */
  allowWholeSystem?: boolean
  wholeSystem?: boolean
  onWholeSystemChange?: (wholeSystem: boolean) => void
  wholeSystemLabel?: string
  /** Shown under the picker when there are no targets and whole-system is off. */
  emptyHint?: string
  idPrefix?: string
  disabled?: boolean
  className?: string
}

export function TargetPicker({
  threatModelId,
  value,
  onChange,
  allowWholeSystem = false,
  wholeSystem = false,
  onWholeSystemChange,
  wholeSystemLabel = 'Applies to the whole system (no targets)',
  emptyHint,
  idPrefix = 'target-picker',
  disabled = false,
  className,
}: TargetPickerProps) {
  const { options, byKey, isLoading } = useModelTargets(threatModelId)

  const comboboxOptions = useMemo(
    (): ComboboxOption[] => options.map((option) => ({ value: option.key, label: option.label, meta: option.typeLabel })),
    [options]
  )
  const selectedKeys = value.map(targetKey)

  return (
    <div className={cn('space-y-2', className)}>
      <MultiSelectCombobox
        options={comboboxOptions}
        selected={selectedKeys}
        onChange={(keys) => {
          const next = keys
            .map((key) => byKey.get(key)?.ref)
            .filter((ref): ref is TargetRef => ref !== undefined)
          onChange(next)
          if (next.length > 0 && wholeSystem) onWholeSystemChange?.(false)
        }}
        placeholder={isLoading ? 'Loading targets' : 'Add a target: a component, flow, zone or boundary'}
        searchPlaceholder="Search targets"
        emptyMessage="No target matches"
        className={cn((disabled || wholeSystem) && 'pointer-events-none opacity-60')}
      />
      {allowWholeSystem && (
        <div className="flex items-center gap-2">
          <Checkbox
            id={`${idPrefix}-whole-system`}
            checked={wholeSystem}
            disabled={disabled}
            onCheckedChange={(checked) => {
              const next = checked === true
              onWholeSystemChange?.(next)
              if (next) onChange([])
            }}
          />
          <Label htmlFor={`${idPrefix}-whole-system`} className="text-sm font-normal">
            {wholeSystemLabel}
          </Label>
        </div>
      )}
      {emptyHint && value.length === 0 && !wholeSystem && (
        <p className="text-xs text-muted-foreground">{emptyHint}</p>
      )}
    </div>
  )
}
