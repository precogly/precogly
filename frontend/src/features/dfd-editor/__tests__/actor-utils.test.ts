import { describe, it, expect } from 'vitest'
import {
  PREDEFINED_ACTORS,
  actorSelectValue,
  commonActorsNotYetAdded,
  personaForCommonActor,
} from '../components/threat-analysis/actor-utils'

const hacktivist = PREDEFINED_ACTORS.find((actor) => actor.value === 'hacktivist')!
const stateActor = PREDEFINED_ACTORS.find((actor) => actor.value === 'state-actor')!

describe('common threat actors', () => {
  it('use CycloneDX persona archetypes as symbolic names', () => {
    expect(stateActor.symbolicName).toBe('nation-state')
    expect(PREDEFINED_ACTORS.map((actor) => actor.symbolicName)).toEqual([
      'nation-state',
      'hacktivist',
      'insider-threat',
      'competitor',
      'opportunist',
      'organized-crime',
    ])
  })

  it('find a threat actor added before, by symbolic name or by name', () => {
    const personas = [
      { id: 1, symbolicName: 'nation-state', name: 'APT from abroad' },
      { id: 2, symbolicName: 'hacktivist-group', name: 'hacktivist' },
    ]
    expect(personaForCommonActor(personas, stateActor)?.id).toBe(1)
    expect(personaForCommonActor(personas, hacktivist)?.id).toBe(2)
    expect(personaForCommonActor([], hacktivist)).toBeUndefined()
  })

  it('list only the common ones not yet added', () => {
    const remaining = commonActorsNotYetAdded([{ id: 1, symbolicName: 'nation-state', name: 'State Actor' }])
    expect(remaining.map((actor) => actor.value)).not.toContain('state-actor')
    expect(remaining).toHaveLength(PREDEFINED_ACTORS.length - 1)
  })

  it('still reads a threat that stores a common actor as text', () => {
    expect(actorSelectValue({ actorPersona: null, threatActorText: 'Hacktivist' })).toBe('hacktivist')
    expect(actorSelectValue({ actorPersona: 4, threatActorText: '' })).toBe('persona:4')
    expect(actorSelectValue({ actorPersona: null, threatActorText: 'A bored teenager' })).toBe('custom')
  })
})
