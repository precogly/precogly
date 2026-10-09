/**
 * The business objectives picker on a threat (plan J4). It renders nothing
 * until the model has at least one objective; the risk detail can reuse it.
 */

import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { useBusinessObjectives } from '@/features/threat-models/api/threat-models'

interface BusinessObjectivesPickerProps {
  threatModelId: string
  value: number[]
  onChange: (objectiveIds: number[]) => void
  disabled?: boolean
  className?: string
}

export function BusinessObjectivesPicker({ threatModelId, value, onChange, disabled, className }: BusinessObjectivesPickerProps) {
  const { data: objectives = [] } = useBusinessObjectives(threatModelId)
  if (objectives.length === 0) return null

  return (
    <MultiSelectCombobox
      options={objectives.map((objective) => ({
        value: String(objective.id),
        label: objective.name,
        meta: objective.criticality || undefined,
      }))}
      selected={value.map(String)}
      onChange={(selected) => onChange(selected.map(Number))}
      placeholder="Add an objective"
      searchPlaceholder="Search objectives"
      emptyMessage="No objective matches"
      className={disabled ? `pointer-events-none opacity-60 ${className ?? ''}` : className}
    />
  )
}
