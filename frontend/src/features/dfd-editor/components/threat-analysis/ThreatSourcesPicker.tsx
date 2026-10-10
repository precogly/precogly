/**
 * The threat sources of a scenario as a small checkbox list. There are only
 * a few sources, so each shows its name with the description as help text.
 */

import { Checkbox } from '@/components/ui/checkbox'
import { useThreatSources } from '@/features/threat-models/api/threats'
import { toggleThreatSourceId } from './threat-source-selection'

interface ThreatSourcesPickerProps {
  value: number[]
  onChange: (threatSourceIds: number[]) => void
}

export function ThreatSourcesPicker({ value, onChange }: ThreatSourcesPickerProps) {
  const { data: threatSources = [] } = useThreatSources()
  if (threatSources.length === 0) return null

  return (
    <div className="space-y-1.5">
      {threatSources.map((source) => {
        const checkboxId = `threat-source-${source.id}`
        return (
          <div key={source.id} className="flex items-start gap-2">
            <Checkbox
              id={checkboxId}
              checked={value.includes(source.id)}
              onCheckedChange={(checked) => onChange(toggleThreatSourceId(value, source.id, checked === true))}
              className="mt-0.5"
            />
            <label htmlFor={checkboxId} className="text-xs leading-tight" title={source.description || undefined}>
              {source.name}
              {source.description && <span className="block text-[11px] text-muted-foreground">{source.description}</span>}
            </label>
          </div>
        )
      })}
    </div>
  )
}
