/**
 * The one-actor rule's value helpers (plan J10, K3), kept out of the picker
 * component so fast refresh works.
 */

/** The built-in actors; they map to spec archetypes on export (section 9.4, G4). */
export const PREDEFINED_ACTORS = [
  { value: 'state-actor', label: 'State Actor' },
  { value: 'hacktivist', label: 'Hacktivist' },
  { value: 'insider-threat', label: 'Insider Threat' },
  { value: 'competitor', label: 'Competitor' },
  { value: 'opportunist', label: 'Opportunist' },
  { value: 'organized-crime', label: 'Organized Crime' },
] as const

export const PERSONA_PREFIX = 'persona:'

export interface ActorValue {
  actorPersona: number | null
  threatActorText: string
}

export const NO_ACTOR: ActorValue = { actorPersona: null, threatActorText: '' }

/** The select's value for an actor: `persona:3`, a built-in slug, `custom` or `none`. */
export function actorSelectValue(value: ActorValue): string {
  if (value.actorPersona !== null) return `${PERSONA_PREFIX}${value.actorPersona}`
  if (!value.threatActorText) return 'none'
  const predefined = PREDEFINED_ACTORS.find((actor) => actor.label === value.threatActorText)
  return predefined ? predefined.value : 'custom'
}
