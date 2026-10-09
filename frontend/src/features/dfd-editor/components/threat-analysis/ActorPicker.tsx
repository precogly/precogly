/**
 * The one-actor picker (plan J10, K3): a persona of the model, one of the
 * six built-in actors, free text, or none. A threat has `actorPersona` or
 * `threatActorText`, never both; choosing one clears the other.
 */

import { useState } from 'react'
import { Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ThreatPersona } from '@/features/threat-models/api/threats'
import { ManagePersonasDialog } from './ManagePersonasDialog'
import { NO_ACTOR, PERSONA_PREFIX, PREDEFINED_ACTORS, actorSelectValue, type ActorValue } from './actor-utils'

interface ActorPickerProps {
  threatModelId: string
  personas: ThreatPersona[]
  value: ActorValue
  onChange: (value: ActorValue) => void
  disabled?: boolean
  /** Hide the "Manage personas" button (for the Add threat dialog). */
  compact?: boolean
}

export function ActorPicker({ threatModelId, personas, value, onChange, disabled = false, compact = false }: ActorPickerProps) {
  const [managePersonasOpen, setManagePersonasOpen] = useState(false)
  const selectValue = actorSelectValue(value)
  const [customMode, setCustomMode] = useState(selectValue === 'custom')
  const showCustomInput = customMode || selectValue === 'custom'

  const handleSelect = (next: string) => {
    if (next === 'none') {
      setCustomMode(false)
      onChange(NO_ACTOR)
    } else if (next === 'custom') {
      setCustomMode(true)
      onChange({ actorPersona: null, threatActorText: '' })
    } else if (next.startsWith(PERSONA_PREFIX)) {
      setCustomMode(false)
      onChange({ actorPersona: Number.parseInt(next.slice(PERSONA_PREFIX.length), 10), threatActorText: '' })
    } else {
      setCustomMode(false)
      const predefined = PREDEFINED_ACTORS.find((actor) => actor.value === next)
      onChange({ actorPersona: null, threatActorText: predefined?.label ?? next })
    }
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        <Select value={showCustomInput ? 'custom' : selectValue} onValueChange={handleSelect} disabled={disabled}>
          <SelectTrigger className="h-7 text-xs" aria-label="Actor">
            <SelectValue placeholder="Select actor" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">
              <span className="text-muted-foreground">None</span>
            </SelectItem>
            {personas.length > 0 && (
              <SelectGroup>
                <SelectLabel className="text-[10px]">Threat personas</SelectLabel>
                {personas.map((persona) => (
                  <SelectItem key={persona.id} value={`${PERSONA_PREFIX}${persona.id}`}>
                    {persona.name}
                  </SelectItem>
                ))}
              </SelectGroup>
            )}
            <SelectGroup>
              <SelectLabel className="text-[10px]">Built-in actors</SelectLabel>
              {PREDEFINED_ACTORS.map((actor) => (
                <SelectItem key={actor.value} value={actor.value}>
                  {actor.label}
                </SelectItem>
              ))}
            </SelectGroup>
            <SelectItem value="custom">
              <span className="text-blue-600">Custom text</span>
            </SelectItem>
          </SelectContent>
        </Select>
        {!compact && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 shrink-0 gap-1 px-2 text-xs"
            onClick={() => setManagePersonasOpen(true)}
            disabled={disabled}
          >
            <Users className="h-3 w-3" />
            Manage personas
          </Button>
        )}
      </div>
      {showCustomInput && (
        <Input
          value={value.threatActorText}
          onChange={(event) => onChange({ actorPersona: null, threatActorText: event.target.value })}
          placeholder="Who is the actor?"
          className="h-7 text-xs"
          disabled={disabled}
          aria-label="Custom actor"
        />
      )}
      {!compact && (
        <ManagePersonasDialog
          open={managePersonasOpen}
          onOpenChange={setManagePersonasOpen}
          threatModelId={threatModelId}
        />
      )}
    </div>
  )
}
