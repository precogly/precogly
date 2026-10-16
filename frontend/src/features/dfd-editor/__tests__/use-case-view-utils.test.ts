import { describe, it, expect } from 'vitest'
import {
  abuseCaseHasNoThreat,
  abuseCasesForColumnEntry,
  buildAddThreatPreset,
  buildUseCaseTree,
  filterLinkableThreats,
  threatsForUseCaseSelection,
  columnEntryForSelection,
} from '../components/threat-analysis/use-case-view-utils'
import type { AbuseCase, UseCase } from '@/features/threat-models/types/core'
import type { AnalysisThreat } from '../types/threat-analysis'

function makeUseCase(id: number, options: Partial<UseCase> = {}): UseCase {
  return {
    id,
    name: `Use case ${id}`,
    description: '',
    flowData: null,
    displayOrder: id,
    components: [],
    flows: [],
    businessObjectives: [],
    abuseCaseCount: 0,
    createdAt: '',
    updatedAt: '',
    ...options,
  }
}

function makeAbuseCase(id: number, useCaseIds: number[], options: Partial<AbuseCase> = {}): AbuseCase {
  return {
    id,
    name: `Abuse case ${id}`,
    description: '',
    flowData: null,
    displayOrder: id,
    abuser: null,
    useCases: useCaseIds.map((useCaseId) => ({ id: useCaseId, name: `Use case ${useCaseId}` })),
    components: [],
    flows: [],
    threats: [],
    unlinkedRealizes: [],
    mitigations: [],
    createdAt: '',
    updatedAt: '',
    ...options,
  }
}

function makeThreat(backendThreatId: number): AnalysisThreat {
  return {
    id: `threat-${backendThreatId}`,
    backendThreatId,
    number: backendThreatId,
    displayNumber: `T${backendThreatId}`,
    threatName: `Threat ${backendThreatId}`,
  } as AnalysisThreat
}

const threatRef = (id: number) => ({ id, number: id, displayNumber: `T${id}`, name: `Threat ${id}` })

describe('buildUseCaseTree', () => {
  it('keeps use cases in the order returned and nests their abuse cases', () => {
    const tree = buildUseCaseTree(
      [makeUseCase(2), makeUseCase(1)],
      [makeAbuseCase(10, [1]), makeAbuseCase(11, [2]), makeAbuseCase(12, [1])]
    )
    expect(tree.useCaseNodes.map((node) => node.useCase.id)).toEqual([2, 1])
    expect(tree.useCaseNodes[0].abuseCases.map((abuseCase) => abuseCase.id)).toEqual([11])
    expect(tree.useCaseNodes[1].abuseCases.map((abuseCase) => abuseCase.id)).toEqual([10, 12])
  })

  it('puts abuse cases with no use case in the "not linked" group', () => {
    const tree = buildUseCaseTree([makeUseCase(1)], [makeAbuseCase(10, [1]), makeAbuseCase(11, [])])
    expect(tree.unlinkedAbuseCases.map((abuseCase) => abuseCase.id)).toEqual([11])
  })

  it('shows an abuse case linked to two use cases under each', () => {
    const tree = buildUseCaseTree([makeUseCase(1), makeUseCase(2)], [makeAbuseCase(10, [1, 2])])
    expect(tree.useCaseNodes[0].abuseCases).toHaveLength(1)
    expect(tree.useCaseNodes[1].abuseCases).toHaveLength(1)
    expect(tree.unlinkedAbuseCases).toHaveLength(0)
  })

  it('adds gap badges and clears them', () => {
    const linked = makeUseCase(2, { components: [{ id: 5, name: 'API', blueprintId: 1 }] })
    const tree = buildUseCaseTree([makeUseCase(1), linked], [makeAbuseCase(10, [2])])
    expect(tree.useCaseNodes[0].gaps).toEqual(['not-analyzed', 'not-linked'])
    expect(tree.useCaseNodes[1].gaps).toEqual([])
  })

  it('flags an abuse case that realizes no threat', () => {
    expect(abuseCaseHasNoThreat(makeAbuseCase(1, [], { threats: [] }))).toBe(true)
    expect(abuseCaseHasNoThreat(makeAbuseCase(1, [], { threats: [threatRef(3)] }))).toBe(false)
  })
})

describe('threatsForUseCaseSelection', () => {
  const analysisThreats = [makeThreat(1), makeThreat(2), makeThreat(3)]
  const abuseCases = [
    makeAbuseCase(10, [1], { threats: [threatRef(1), threatRef(2)] }),
    makeAbuseCase(11, [1], { threats: [threatRef(2), threatRef(3)] }),
    makeAbuseCase(12, [2], { threats: [threatRef(3)] }),
  ]

  it('lists the threats of an abuse case', () => {
    const result = threatsForUseCaseSelection({ kind: 'abuseCase', abuseCaseId: 10 }, abuseCases, analysisThreats)
    expect(result.map((threat) => threat.backendThreatId)).toEqual([1, 2])
  })

  it('lists the threats of all abuse cases of a use case, each once', () => {
    const result = threatsForUseCaseSelection({ kind: 'useCase', useCaseId: 1 }, abuseCases, analysisThreats)
    expect(result.map((threat) => threat.backendThreatId)).toEqual([1, 2, 3])
  })

  it('returns the same row objects as the analysis payload and skips ids with no row', () => {
    const result = threatsForUseCaseSelection({ kind: 'useCase', useCaseId: 2 }, abuseCases, [analysisThreats[0]])
    expect(result).toEqual([])
    const found = threatsForUseCaseSelection({ kind: 'abuseCase', abuseCaseId: 10 }, abuseCases, analysisThreats)
    expect(found[0]).toBe(analysisThreats[0])
  })

  it('returns nothing without a selection', () => {
    expect(threatsForUseCaseSelection(null, abuseCases, analysisThreats)).toEqual([])
  })
})

describe('buildAddThreatPreset', () => {
  const useCases = [
    makeUseCase(1, {
      components: [{ id: 5, name: 'API', blueprintId: 1 }],
      flows: [{ id: 7, name: '', sourceName: 'A', destinationName: 'B', blueprintId: 1 }],
    }),
    makeUseCase(2, { components: [{ id: 5, name: 'API', blueprintId: 1 }, { id: 6, name: 'DB', blueprintId: 1 }] }),
  ]

  it('selects the abuse case targets and sets the actor from the abuser', () => {
    const abuseCase = makeAbuseCase(10, [1], {
      abuser: { id: 4, name: 'Fraudster' },
      components: [{ id: 9, name: 'Checkout', blueprintId: 1 }],
      flows: [{ id: 8, name: '', sourceName: 'A', destinationName: 'B', blueprintId: 1 }],
    })
    const preset = buildAddThreatPreset(abuseCase, useCases)
    expect(preset.initialTargets).toEqual([
      { type: 'component', id: 9 },
      { type: 'flow', id: 8 },
    ])
    expect(preset.suggestedTargets).toEqual([])
    expect(preset.initialActor).toEqual({ actorPersona: 4, threatActorText: '' })
  })

  it('suggests the use case parts, once each, when the abuse case has no targets', () => {
    const preset = buildAddThreatPreset(makeAbuseCase(10, [1, 2]), useCases)
    expect(preset.initialTargets).toEqual([])
    expect(preset.suggestedTargets).toEqual([
      { type: 'component', id: 5 },
      { type: 'flow', id: 7 },
      { type: 'component', id: 6 },
    ])
    expect(preset.initialActor).toBeUndefined()
  })

  it('starts empty when neither the abuse case nor its use cases have links', () => {
    const preset = buildAddThreatPreset(makeAbuseCase(10, []), useCases)
    expect(preset.initialTargets).toEqual([])
    expect(preset.suggestedTargets).toEqual([])
  })
})

describe('link existing threat', () => {
  const threats = [
    { backendThreatId: 1, displayNumber: 'T1', threatName: 'SQL injection' },
    { backendThreatId: 12, displayNumber: 'T12', threatName: 'Card testing' },
    { backendThreatId: 3, displayNumber: 'T3', threatName: undefined },
  ]

  it('searches by T number or name and leaves out linked threats', () => {
    expect(filterLinkableThreats(threats, [], 'sql').map((threat) => threat.backendThreatId)).toEqual([1])
    expect(filterLinkableThreats(threats, [], 't12').map((threat) => threat.backendThreatId)).toEqual([12])
    expect(filterLinkableThreats(threats, [1], '').map((threat) => threat.backendThreatId)).toEqual([12, 3])
  })
})

describe('the first two columns', () => {
  const abuseCases = [makeAbuseCase(10, [1, 2]), makeAbuseCase(11, [2]), makeAbuseCase(12, [])]
  const tree = buildUseCaseTree([makeUseCase(1), makeUseCase(2)], abuseCases)

  it('highlights the selected use case and lists its abuse cases', () => {
    const entry = columnEntryForSelection({ kind: 'useCase', useCaseId: 2 }, abuseCases)
    expect(entry).toEqual({ kind: 'useCase', useCaseId: 2 })
    expect(abuseCasesForColumnEntry(entry, tree).map((abuseCase) => abuseCase.id)).toEqual([10, 11])
  })

  it('keeps the use case an abuse case was picked under', () => {
    expect(columnEntryForSelection({ kind: 'abuseCase', abuseCaseId: 10, useCaseId: 2 }, abuseCases)).toEqual({
      kind: 'useCase',
      useCaseId: 2,
    })
  })

  it('falls back to the first use case of an abuse case picked from elsewhere', () => {
    expect(columnEntryForSelection({ kind: 'abuseCase', abuseCaseId: 10 }, abuseCases)).toEqual({ kind: 'useCase', useCaseId: 1 })
  })

  it('puts an abuse case with no use case under "Not linked"', () => {
    const entry = columnEntryForSelection({ kind: 'abuseCase', abuseCaseId: 12 }, abuseCases)
    expect(entry).toEqual({ kind: 'noUseCase' })
    expect(abuseCasesForColumnEntry(entry, tree).map((abuseCase) => abuseCase.id)).toEqual([12])
    expect(columnEntryForSelection({ kind: 'abuseCase', abuseCaseId: 10, useCaseId: null }, abuseCases)).toEqual({
      kind: 'noUseCase',
    })
  })

  it('lists nothing with nothing selected, and no threats for the "Not linked" group itself', () => {
    expect(columnEntryForSelection(null, abuseCases)).toBeNull()
    expect(abuseCasesForColumnEntry(null, tree)).toEqual([])
    expect(threatsForUseCaseSelection({ kind: 'noUseCase' }, abuseCases, [])).toEqual([])
  })
})
