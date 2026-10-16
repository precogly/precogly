import { describe, expect, it } from 'vitest'
import type { Blueprint, BlueprintDeletePreview } from '../types/core'
import {
  blueprintFormErrors,
  deletePreviewLines,
  groupByBlueprint,
  nextDisplayOrder,
  reorderBlueprints,
  resolveSelectedBlueprintId,
  showsBlueprintChoice,
  sortBlueprints,
} from '../components/workspace/blueprint-utils'

function blueprint(id: number, name: string, displayOrder: number): Blueprint {
  return {
    id,
    threatModel: 1,
    name,
    description: '',
    modelTypes: [],
    scopeDescription: '',
    displayOrder,
    formatMetadata: {},
    createdAt: '2026-10-01T00:00:00Z',
    updatedAt: '2026-10-01T00:00:00Z',
  }
}

const plantNetwork = blueprint(2, 'Plant network view', 1)
const dataFlow = blueprint(1, 'Data flow view', 0)

describe('resolveSelectedBlueprintId', () => {
  it('keeps a requested blueprint that exists and falls back to the first otherwise', () => {
    const blueprints = [plantNetwork, dataFlow]
    expect(resolveSelectedBlueprintId(2, blueprints)).toBe(2)
    expect(resolveSelectedBlueprintId(99, blueprints)).toBe(1)
    expect(resolveSelectedBlueprintId(null, blueprints)).toBe(1)
    expect(resolveSelectedBlueprintId(1, [])).toBeNull()
  })

  it('shows the blueprint choice only with more than one blueprint', () => {
    expect(showsBlueprintChoice([dataFlow])).toBe(false)
    expect(showsBlueprintChoice([dataFlow, plantNetwork])).toBe(true)
  })
})

describe('groupByBlueprint', () => {
  const rows = [
    { id: 10, blueprint: 2, name: 'Office Wi-Fi' },
    { id: 11, blueprint: 1, name: 'Billing' },
    { id: 12, blueprint: 2, name: 'Building access' },
    { id: 13, blueprint: 7, name: 'Orphan' },
  ]

  it('groups rows in blueprint display order and keeps unknown blueprints in a trailing group', () => {
    const groups = groupByBlueprint(rows, [plantNetwork, dataFlow])
    expect(groups.map((group) => group.blueprint?.name ?? null)).toEqual([
      'Data flow view',
      'Plant network view',
      null,
    ])
    expect(groups[0].items.map((row) => row.id)).toEqual([11])
    expect(groups[1].items.map((row) => row.id)).toEqual([10, 12])
    expect(groups[2].items.map((row) => row.id)).toEqual([13])
  })

  it('leaves out empty groups', () => {
    const groups = groupByBlueprint([rows[1]], [dataFlow, plantNetwork])
    expect(groups).toHaveLength(1)
    expect(groups[0].blueprint?.id).toBe(1)
  })

  it('sorts by display order, then id', () => {
    const tie = blueprint(3, 'Tie', 0)
    expect(sortBlueprints([plantNetwork, tie, dataFlow]).map((item) => item.id)).toEqual([1, 3, 2])
  })
})

describe('deletePreviewLines', () => {
  const preview: BlueprintDeletePreview = {
    blueprint: { id: 2, name: 'Plant network view' },
    isLast: false,
    components: 5,
    flows: 8,
    zones: 3,
    boundaries: 1,
    diagrams: 1,
    dataAssets: 2,
    outOfScopeItems: 0,
    assumptions: 1,
    threatsDeleted: 6,
    threatsLosingTargets: 2,
  }

  it('lists the counts that are not zero and the threats that go or shrink', () => {
    expect(deletePreviewLines(preview)).toEqual([
      '5 components, 8 flows, 3 zones, 1 boundary, 1 diagram, 2 data assets, 1 assumption',
      '6 threats that only sit on things in this blueprint',
      '2 threats also on other blueprints stay and lose the targets here',
    ])
    expect(deletePreviewLines({ ...preview, threatsLosingTargets: 1 })[2]).toBe(
      '1 threat also on other blueprints stays and loses the targets here'
    )
  })

  it('is empty for an empty blueprint', () => {
    expect(
      deletePreviewLines({
        ...preview,
        components: 0,
        flows: 0,
        zones: 0,
        boundaries: 0,
        diagrams: 0,
        dataAssets: 0,
        assumptions: 0,
        threatsDeleted: 0,
        threatsLosingTargets: 0,
      })
    ).toEqual([])
  })
})

describe('ordering', () => {
  it('places a new blueprint after the last one', () => {
    expect(nextDisplayOrder([])).toBe(0)
    expect(nextDisplayOrder([dataFlow, plantNetwork])).toBe(2)
  })

  it('swaps neighbours and renumbers collided orders', () => {
    const first = blueprint(1, 'A', 0)
    const second = blueprint(2, 'B', 0)
    const third = blueprint(3, 'C', 0)
    expect(reorderBlueprints([first, second, third], 2, 'up')).toEqual([
      { blueprintId: 3, displayOrder: 1 },
      { blueprintId: 2, displayOrder: 2 },
    ])
    expect(reorderBlueprints([first, second, third], 0, 'up')).toEqual([])
    expect(reorderBlueprints([first, second, third], 2, 'down')).toEqual([])
  })
})

describe('blueprintFormErrors', () => {
  it('asks for a name and a model type when both are missing', () => {
    expect(blueprintFormErrors({ name: '   ', modelTypes: [] })).toEqual({
      name: 'Give the blueprint a name.',
      modelTypes: 'Choose at least one model type.',
    })
  })

  it('is empty when the required fields are filled', () => {
    expect(blueprintFormErrors({ name: 'Electrical', modelTypes: ['physical'] })).toEqual({})
  })
})
