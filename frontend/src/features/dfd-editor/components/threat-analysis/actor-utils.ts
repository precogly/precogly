/**
 * The one-actor rule's value helpers (plan J10, K3), kept out of the picker
 * component so fast refresh works.
 */

/**
 * The common threat actors (once called built-in actors). Picking one adds it
 * to the model's threat actors, stored as a persona whose symbolic name is the
 * CycloneDX persona archetype, so the export keeps the type (section 9.4, G4).
 * "Opportunist" has no archetype of its own and exports as "attacker".
 */
export const PREDEFINED_ACTORS = [
  { value: 'state-actor', label: 'State Actor', symbolicName: 'nation-state' },
  { value: 'hacktivist', label: 'Hacktivist', symbolicName: 'hacktivist' },
  { value: 'insider-threat', label: 'Insider Threat', symbolicName: 'insider-threat' },
  { value: 'competitor', label: 'Competitor', symbolicName: 'competitor' },
  { value: 'opportunist', label: 'Opportunist', symbolicName: 'opportunist' },
  { value: 'organized-crime', label: 'Organized Crime', symbolicName: 'organized-crime' },
] as const

export type PredefinedActor = (typeof PREDEFINED_ACTORS)[number]

/**
 * The model's threat actor for a common one, if it was added before: same
 * symbolic name, or the same name ignoring case.
 */
export function personaForCommonActor<Persona extends { id: number; symbolicName: string; name: string }>(
  personas: Persona[],
  actor: PredefinedActor
): Persona | undefined {
  return personas.find(
    (persona) =>
      persona.symbolicName === actor.symbolicName || persona.name.trim().toLowerCase() === actor.label.toLowerCase()
  )
}

/** The common threat actors not yet among the model's own, so the list shows each once. */
export function commonActorsNotYetAdded<Persona extends { id: number; symbolicName: string; name: string }>(
  personas: Persona[]
): PredefinedActor[] {
  return PREDEFINED_ACTORS.filter((actor) => !personaForCommonActor(personas, actor))
}

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
