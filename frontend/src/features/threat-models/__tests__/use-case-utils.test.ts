import { describe, expect, it } from 'vitest'
import type { AbuseCase, UseCase } from '../types/core'
import {
  initialAbuseCaseForm,
  buildAbuseCaseInput,
  buildUseCaseInput,
  errorMessages,
  formatFlowLabel,
  initialUseCaseForm,
  getUseCaseGaps,
} from '../components/use-cases/use-case-utils'

function useCase(overrides: Partial<UseCase> = {}): UseCase {
  return {
    id: 1,
    name: 'Place Order',
    description: '',
    flowData: null,
    displayOrder: 0,
    components: [],
    flows: [],
    businessObjectives: [],
    abuseCaseCount: 0,
    createdAt: '',
    updatedAt: '',
    ...overrides,
  }
}

function abuseCase(overrides: Partial<AbuseCase> = {}): AbuseCase {
  return {
    id: 5,
    name: 'Card testing',
    description: '',
    flowData: null,
    displayOrder: 0,
    abuser: null,
    useCases: [],
    components: [],
    flows: [],
    threats: [],
    unlinkedRealizes: [],
    mitigations: [],
    createdAt: '',
    updatedAt: '',
    ...overrides,
  }
}

describe('formatFlowLabel', () => {
  it('shows the name in parentheses', () => {
    expect(formatFlowLabel({ name: 'Login', sourceName: 'Web', destinationName: 'API' })).toBe('Web to API (Login)')
  })
  it('omits empty parentheses', () => {
    expect(formatFlowLabel({ name: '  ', sourceName: 'Web', destinationName: 'API' })).toBe('Web to API')
  })
})

describe('getUseCaseGaps', () => {
  it('flags a use case without abuse cases and links', () => {
    expect(getUseCaseGaps(useCase())).toEqual(['not-analyzed', 'not-linked'])
  })
  it('has no gaps when analyzed and linked', () => {
    const linked = useCase({
      abuseCaseCount: 2,
      components: [{ id: 1, name: 'API', blueprintId: 1 }],
    })
    expect(getUseCaseGaps(linked)).toEqual([])
  })
  it('a flow alone counts as linked', () => {
    const linked = useCase({
      abuseCaseCount: 1,
      flows: [{ id: 1, name: '', sourceName: 'A', destinationName: 'B', blueprintId: 1 }],
    })
    expect(getUseCaseGaps(linked)).toEqual([])
  })
})

describe('buildUseCaseInput', () => {
  it('sends the edited ids and flowData', () => {
    const state = initialUseCaseForm(useCase())
    state.name = '  Refund  '
    state.componentIds = [3, 4]
    state.flowIds = [9]
    state.businessObjectiveIds = [2]
    state.preconditions = ['Logged in']
    state.mainFlow = [{ description: 'Open order' }]
    const input = buildUseCaseInput(state, true)
    expect(input.name).toBe('Refund')
    expect(input.componentIds).toEqual([3, 4])
    expect(input.flowIds).toEqual([9])
    expect(input.businessObjectiveIds).toEqual([2])
    expect(input.flowData?.preconditions).toEqual(['Logged in'])
    expect(input.flowData?.mainFlow).toEqual([{ description: 'Open order' }])
  })

  it('does not send empty rows or empty lists', () => {
    const state = initialUseCaseForm(useCase())
    state.name = 'X'
    state.preconditions = ['', '  ']
    state.mainFlow = [{ description: ' ' }]
    state.alternativeFlows = [{ name: '', condition: '' }]
    state.exceptions = [{ name: '', condition: '', handling: '' }]
    expect(buildUseCaseInput(state, true).flowData).toEqual({})
  })

  it('keeps an imported step actor and unknown keys', () => {
    const saved = useCase({
      flowData: { notes: ['n'], mainFlow: [{ number: 1, description: 'Pay', actor: 'customer' }], custom: 1 },
    })
    const state = initialUseCaseForm(saved)
    state.mainFlow = [{ ...state.mainFlow[0], description: ' Pay now ' }]
    const flowData = buildUseCaseInput(state, true).flowData
    expect(flowData?.mainFlow?.[0].actor).toBe('customer')
    expect(flowData?.mainFlow?.[0].description).toBe('Pay now')
    expect(flowData?.notes).toEqual(['n'])
    expect(flowData?.custom).toBe(1)
  })

  it('clears a saved list when its last row is removed', () => {
    const state = initialUseCaseForm(useCase({ flowData: { preconditions: ['a'] } }))
    state.preconditions = []
    expect(buildUseCaseInput(state, true).flowData?.preconditions).toEqual([])
  })

  it('leaves business objectives out when the model has none', () => {
    const state = initialUseCaseForm(useCase({ businessObjectives: [{ id: 1, name: 'Obj' }] }))
    expect('businessObjectiveIds' in buildUseCaseInput(state, false)).toBe(false)
  })

  it('keeps exception handling as one string and drops empty optional fields', () => {
    const state = initialUseCaseForm(useCase())
    state.name = 'X'
    state.exceptions = [{ name: 'Timeout', condition: 'Bank is slow', description: ' ', handling: ' Retry ' }]
    expect(buildUseCaseInput(state, true).flowData?.exceptions).toEqual([
      { name: 'Timeout', condition: 'Bank is slow', handling: 'Retry' },
    ])
  })
})

describe('buildAbuseCaseInput', () => {
  it('presets the default use case on create', () => {
    expect(initialAbuseCaseForm(undefined, 7).useCaseIds).toEqual([7])
  })

  it('does not preset the default use case when editing', () => {
    const state = initialAbuseCaseForm(abuseCase({ useCases: [{ id: 2, name: 'A' }] }), 7)
    expect(state.useCaseIds).toEqual([2])
  })

  it('sends abuser, links and flowData, and no threat ids', () => {
    const state = initialAbuseCaseForm(undefined, 7)
    state.name = ' Card testing '
    state.abuserId = 4
    state.componentIds = [1]
    state.detectionOpportunities = ['Alert on spikes', '']
    state.mainFlow = [{ description: 'Try cards', actor: 'attacker' }]
    const input = buildAbuseCaseInput(state)
    expect(input).toMatchObject({
      name: 'Card testing',
      abuserId: 4,
      useCaseIds: [7],
      componentIds: [1],
      flowIds: [],
    })
    expect(input.flowData?.detectionOpportunities).toEqual(['Alert on spikes'])
    expect(input.flowData?.mainFlow?.[0].actor).toBe('attacker')
    expect('threatIds' in input).toBe(false)
  })

  it('loads the description when editing and sends it trimmed', () => {
    const state = initialAbuseCaseForm(abuseCase({ description: 'Tests stolen cards' }))
    expect(state.description).toBe('Tests stolen cards')
    state.description = '  Tests many cards  '
    expect(buildAbuseCaseInput(state).description).toBe('Tests many cards')
    expect(initialAbuseCaseForm(undefined).description).toBe('')
  })

  it('sends a null abuser to clear it', () => {
    const state = initialAbuseCaseForm(abuseCase({ abuser: { id: 3, name: 'P' } }))
    state.abuserId = null
    expect(buildAbuseCaseInput(state).abuserId).toBeNull()
  })
})

describe('errorMessages', () => {
  it('flattens a backend body', () => {
    const error = Object.assign(new Error('API Error: 400'), { data: { flowData: ['Step 1 needs a description.'] } })
    expect(errorMessages(error, 'x')).toEqual(['Step 1 needs a description.'])
  })
  it('falls back to the error message', () => {
    expect(errorMessages(new Error('boom'), 'x')).toEqual(['boom'])
    expect(errorMessages(null, 'fallback')).toEqual(['fallback'])
  })
})
