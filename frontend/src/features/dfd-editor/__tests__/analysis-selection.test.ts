import { describe, it, expect } from 'vitest'
import {
  SYSTEM_SELECTION,
  canvasElementSelection,
  threatHomeSelection,
} from '../components/threat-analysis/analysis-selection'
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
