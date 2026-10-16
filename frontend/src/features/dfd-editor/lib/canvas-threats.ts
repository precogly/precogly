import { isActiveThreat } from '@/types/triage'
import { threatTargetsCanvasId, type AnalysisThreat } from '../types/threat-analysis'

export interface CanvasThreats {
  /** Listed as cards, in payload order. */
  active: AnalysisThreat[]
  /** Accepted, mitigated, delegated or eliminated: shown collapsed, so they can be reopened. */
  triaged: AnalysisThreat[]
}

/** The threats targeting one canvas element, split by whether they are still active. */
export function canvasThreats(threats: readonly AnalysisThreat[] | undefined, canvasId: string): CanvasThreats {
  const active: AnalysisThreat[] = []
  const triaged: AnalysisThreat[] = []
  for (const threat of threats ?? []) {
    if (!threatTargetsCanvasId(threat, canvasId)) continue
    if (isActiveThreat(threat.triageStatus)) active.push(threat)
    else triaged.push(threat)
  }
  return { active, triaged }
}

/**
 * The threat the modal is open on, active or triaged, so triaging in the
 * modal keeps it open on the fresh row; null once the threat is no longer
 * on this element (deleted, or its targets changed).
 */
export function openCanvasThreat(threats: CanvasThreats, openThreatId: string | null): AnalysisThreat | null {
  if (openThreatId === null) return null
  return [...threats.active, ...threats.triaged].find((threat) => threat.id === openThreatId) ?? null
}
