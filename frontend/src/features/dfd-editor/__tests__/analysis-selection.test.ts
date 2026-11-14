import { describe, it, expect } from 'vitest'
import {
  SYSTEM_SELECTION,
  canvasElementSelection,
  targetSelection,
  threatHomeSelection,
  threatInSelectionSubtree,
  treeKeyForSelection,
} from '../components/threat-analysis/analysis-selection'
import { buildAnalysisTree } from '../components/threat-analysis/hierarchy-utils'
import type { AnalysisThreat } from '../types/threat-analysis'

const maps = {
  nodeComponentMap: { 'node-plc': { componentId: 7 } },
  edgeFlowMap: { 'edge-signals': { flowId: 21 } },
}

describe('canvasElementSelection', () => {
  it('maps a canvas node to its component and an edge to its flow', () => {
    expect(canvasElementSelection('node-plc', maps)).toEqual({ kind: 'target', type: 'component', id: 7 })
    expect(canvasElementSelection('edge-signals', maps)).toEqual({ kind: 'target', type: 'flow', id: 21 })
  })

  it('gives null for an id on neither map', () => {
    expect(canvasElementSelection('zone-box', maps)).toBeNull()
  })
})

describe('threatHomeSelection', () => {
  const baseThreat = { wholeSystem: false, targets: [] } as unknown as AnalysisThreat

  it('picks the first target', () => {
    const threat = {
      ...baseThreat,
      targets: [
        { type: 'zone', id: 3 },
        { type: 'component', id: 9 },
      ],
    } as unknown as AnalysisThreat
    expect(threatHomeSelection(threat)).toEqual({ kind: 'target', type: 'zone', id: 3 })
  })

  it('picks the system for a whole-system threat', () => {
    expect(threatHomeSelection({ ...baseThreat, wholeSystem: true } as AnalysisThreat)).toEqual(SYSTEM_SELECTION)
  })
})

describe('treeKeyForSelection', () => {
  it('gives the tree row keys the builder uses', () => {
    expect(treeKeyForSelection(SYSTEM_SELECTION)).toBe('system')
    expect(treeKeyForSelection(targetSelection('component', 5))).toBe('component-5')
    expect(treeKeyForSelection(targetSelection('zone', 3))).toBe('zone-3')
    expect(treeKeyForSelection(null)).toBeNull()
  })
})

describe('threatInSelectionSubtree', () => {
  // Zone 10 holds the API (100) with its child Worker (101); the Database (102) sits in no zone.
  const { byKey } = buildAnalysisTree({
    blueprints: [{ id: 1, name: 'Main' }],
    zones: [{ id: 10, name: 'AWS Cloud', blueprint: 1, parent: null }],
    components: [
      { id: 100, name: 'API Gateway', blueprint: 1, zone: 10, parentComponent: null },
      { id: 101, name: 'Worker', blueprint: 1, zone: 10, parentComponent: 100 },
      { id: 102, name: 'Database', blueprint: 1, zone: null, parentComponent: null },
    ],
    flows: [],
    boundaries: [],
    threats: [
      {
        id: 'threat-1',
        wholeSystem: false,
        targets: [{ type: 'component', id: 101 }],
        triageStatus: 'open',
        countermeasures: [],
      } as unknown as AnalysisThreat,
    ],
  })
  const onWorker = { id: 'threat-1' }

  it('is in the parent component\'s, the enclosing zone\'s and the system\'s subtree', () => {
    expect(threatInSelectionSubtree(onWorker, targetSelection('component', 101), byKey)).toBe(true)
    expect(threatInSelectionSubtree(onWorker, targetSelection('component', 100), byKey)).toBe(true)
    expect(threatInSelectionSubtree(onWorker, targetSelection('zone', 10), byKey)).toBe(true)
    expect(threatInSelectionSubtree(onWorker, SYSTEM_SELECTION, byKey)).toBe(true)
  })

  it('is not in a sibling\'s subtree, nor anywhere with no selection', () => {
    expect(threatInSelectionSubtree(onWorker, targetSelection('component', 102), byKey)).toBe(false)
    expect(threatInSelectionSubtree(onWorker, null, byKey)).toBe(false)
  })
})
