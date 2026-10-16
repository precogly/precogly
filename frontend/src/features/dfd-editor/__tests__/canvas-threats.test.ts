import { describe, expect, it } from 'vitest'
import type { AnalysisTarget, AnalysisThreat } from '../types/threat-analysis'
import { canvasThreats, openCanvasThreat } from '../lib/canvas-threats'

function nodeTarget(nodeId: string): AnalysisTarget {
  return { type: 'component', id: 1, name: nodeId, blueprintId: 1, nodeId, edgeId: null, dfdId: '1', dfdName: 'Main' }
}

function makeThreat(backendThreatId: number, nodeId: string, triageStatus: AnalysisThreat['triageStatus'] = 'open'): AnalysisThreat {
  return {
    id: `threat-${backendThreatId}`,
    backendThreatId,
    number: backendThreatId,
    displayNumber: `T${backendThreatId}`,
    threatName: `Threat ${backendThreatId}`,
    triageStatus,
    targets: [nodeTarget(nodeId)],
  } as AnalysisThreat
}

const ids = (threats: AnalysisThreat[]) => threats.map((threat) => threat.id)

describe('canvasThreats', () => {
  it('lists the active threats targeting the canvas element, in payload order', () => {
    const threats = [makeThreat(2, 'node-a'), makeThreat(1, 'node-b'), makeThreat(3, 'node-a')]
    expect(ids(canvasThreats(threats, 'node-a').active)).toEqual(['threat-2', 'threat-3'])
  })

  it('puts a triaged threat in the collapsed group, not the cards', () => {
    const threats = [makeThreat(1, 'node-a', 'accept'), makeThreat(2, 'node-a', 'eliminate'), makeThreat(3, 'node-a')]
    const split = canvasThreats(threats, 'node-a')
    expect(ids(split.active)).toEqual(['threat-3'])
    expect(ids(split.triaged)).toEqual(['threat-1', 'threat-2'])
  })

  it('leaves out a triaged threat of another element', () => {
    expect(canvasThreats([makeThreat(1, 'node-b', 'accept')], 'node-a')).toEqual({ active: [], triaged: [] })
  })

  it('is empty before the payload arrives', () => {
    expect(canvasThreats(undefined, 'node-a')).toEqual({ active: [], triaged: [] })
  })
})

describe('openCanvasThreat', () => {
  const threats = canvasThreats([makeThreat(1, 'node-a'), makeThreat(2, 'node-a', 'accept')], 'node-a')

  it('returns the fresh row for the open id', () => {
    expect(openCanvasThreat(threats, 'threat-1')?.backendThreatId).toBe(1)
  })

  it('still finds a threat once it is triaged, so the modal stays open on it', () => {
    expect(openCanvasThreat(threats, 'threat-2')?.triageStatus).toBe('accept')
  })

  it('is null with nothing open', () => {
    expect(openCanvasThreat(threats, null)).toBeNull()
  })

  it('is null once the open threat has left the element, so the modal closes', () => {
    expect(openCanvasThreat(threats, 'threat-9')).toBeNull()
  })
})
