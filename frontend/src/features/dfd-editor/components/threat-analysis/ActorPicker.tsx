/**
 * The threat actor picker (plan J10, K3), used for a threat's actor and an
 * abuse case's abuser. One list in both places: the model's threat actors,
 * then the common threat actors. Picking a common one adds it to the model's
 * threat actors (or reuses it when it is there already) and selects it, so
 * it exports with its CycloneDX archetype. A threat can also take free text;
 * an abuse case cannot, since the spec's `abuser` is a reference.
 *
 * Stored as a persona (`actorPersona`) or text (`threatActorText`), never
 * both; choosing one clears the other. A threat that stored a common actor
 * as text before this picker still shows it selected.
 */

import { useState } from 'react'
import { toast } from 'sonner'
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
import { useCreateThreatPersona, type ThreatPersona } from '@/features/threat-models/api/threats'
import { ManagePersonasDialog } from './ManagePersonasDialog'
import {
  NO_ACTOR,
  PERSONA_PREFIX,
  PREDEFINED_ACTORS,
  actorSelectValue,
  commonActorsNotYetAdded,
  personaForCommonActor,
  type ActorValue,
} from './actor-utils'

interface ActorPickerProps {
  threatModelId: string
  personas: ThreatPersona[]
  value: ActorValue
  onChange: (value: ActorValue) => void
  disabled?: boolean
  /** Hide the "Manage threat actors" button (for the Add threat dialog). */
  compact?: boolean
  /** Offer "Custom text" (a threat's actor); off for an abuse case's abuser, which must be a reference. */
  allowCustomText?: boolean
  id?: string
}

export function ActorPicker({
  threatModelId,
  personas,
  value,
  onChange,
  disabled = false,
  compact = false,
  allowCustomText = true,
  id,
}: ActorPickerProps) {
  const [managePersonasOpen, setManagePersonasOpen] = useState(false)
  const createPersona = useCreateThreatPersona(threatModelId)
  const selectValue = actorSelectValue(value)
  const [customMode, setCustomMode] = useState(selectValue === 'custom')
  const showCustomInput = allowCustomText && (customMode || selectValue === 'custom')

  // Each common actor shows once: under the model's own when added, else here.
  // One stored as text before keeps its entry, so the select can show it.
  const commonActors = commonActorsNotYetAdded(personas)
  const legacyTextActor = PREDEFINED_ACTORS.find((actor) => actor.value === selectValue)
  if (legacyTextActor && !commonActors.includes(legacyTextActor)) commonActors.push(legacyTextActor)

  const selectCommonActor = async (actorValue: string) => {
    const actor = PREDEFINED_ACTORS.find((candidate) => candidate.value === actorValue)
    if (!actor) return
    const existing = personaForCommonActor(personas, actor)
    if (existing) {
      onChange({ actorPersona: existing.id, threatActorText: '' })
      return
    }
    try {
      const created = await createPersona.mutateAsync({
        symbolicName: actor.symbolicName,
        name: actor.label,
        isPerson: false,
        maliciousIntent: true,
      })
      onChange({ actorPersona: created.id, threatActorText: '' })
    } catch {
      toast.error(`Could not add ${actor.label} to the threat actors`)
    }
  }

  const handleSelect = (next: string) => {
    if (next === selectValue && next !== 'custom') return
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
      void selectCommonActor(next)
    }
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        <Select
          value={showCustomInput ? 'custom' : selectValue}
          onValueChange={handleSelect}
          disabled={disabled || createPersona.isPending}
        >
          <SelectTrigger id={id} className="h-7 text-xs" aria-label="Threat actor">
            <SelectValue placeholder="Select a threat actor" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">
              <span className="text-muted-foreground">None</span>
            </SelectItem>
            {personas.length > 0 && (
              <SelectGroup>
                <SelectLabel className="text-[10px]">This model's threat actors</SelectLabel>
                {personas.map((persona) => (
                  <SelectItem key={persona.id} value={`${PERSONA_PREFIX}${persona.id}`}>
                    {persona.name}
                  </SelectItem>
                ))}
              </SelectGroup>
            )}
            {commonActors.length > 0 && (
              <SelectGroup>
                <SelectLabel className="text-[10px]">Common threat actors</SelectLabel>
                {commonActors.map((actor) => (
                  <SelectItem key={actor.value} value={actor.value}>
                    {actor.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            )}
            {allowCustomText && (
              <SelectItem value="custom">
                <span className="text-blue-600">Custom text</span>
              </SelectItem>
            )}
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
            Manage threat actors
          </Button>
        )}
      </div>
      {showCustomInput && (
        <Input
          value={value.threatActorText}
          onChange={(event) => onChange({ actorPersona: null, threatActorText: event.target.value })}
          placeholder="Who is the threat actor?"
          className="h-7 text-xs"
          disabled={disabled}
          aria-label="Custom threat actor"
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
