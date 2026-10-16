/**
 * Rules of the guest editor's model that the state hooks and the adapter
 * share (plan 11.9).
 *
 * - H9: when deleting diagram elements removes a threat's last target, the
 *   threat is deleted. It never turns into a whole-system threat by accident.
 *   A threat whose remaining targets are all in a hidden blueprint survives.
 * - A countermeasure that loses its last threat is deleted (the guest
 *   editor's cascade); one that loses its last target applies to the whole
 *   system, as the backend reads an empty `appliesTo`.
 * - The derived `precogly:threat-status` follows the backend's
 *   `recalculate_threat_status`, with a control's status read from what the
 *   file carried (new guest controls are `recommended`).
 */

import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { GuestCountermeasure, GuestTargetRef, GuestTargetType, GuestThreat } from '../types'
import { COUNTERMEASURE_STATUS_TO_SPEC, CUSTOM_COUNTERMEASURE_STATUSES } from './cyclonedx-spec.generated'

export interface RemovalResult {
  threats: GuestThreat[]
  countermeasures: GuestCountermeasure[]
  removedThreatIds: string[]
  removedCountermeasureIds: string[]
}

/** Apply the deletion of diagram elements (node and edge ids) to threats and countermeasures. */
export function removeDiagramElements(
  threats: GuestThreat[],
  countermeasures: GuestCountermeasure[],
  deletedIds: ReadonlySet<string>
): RemovalResult {
  const removedThreatIds: string[] = []
  const keptThreats: GuestThreat[] = []
  for (const threat of threats) {
    const targets = threat.targets.filter((target) => !deletedIds.has(target.id))
    if (targets.length === threat.targets.length) {
      keptThreats.push(threat)
      continue
    }
    const stillAttached = targets.length > 0 || threat.wholeSystem || threat.hiddenTargetRefs.length > 0
    if (!stillAttached) {
      removedThreatIds.push(threat.id)
      continue
    }
    keptThreats.push({ ...threat, targets })
  }
  const removed = new Set(removedThreatIds)
  const removedCountermeasureIds: string[] = []
  const keptCountermeasures: GuestCountermeasure[] = []
  for (const countermeasure of countermeasures) {
    const threatIds = countermeasure.threatIds.filter((threatId) => !removed.has(threatId))
    const targets = countermeasure.targets.filter((target) => !deletedIds.has(target.id))
    if (threatIds.length === 0 && countermeasure.threatIds.length > 0) {
      removedCountermeasureIds.push(countermeasure.id)
      continue
    }
    if (threatIds.length === countermeasure.threatIds.length && targets.length === countermeasure.targets.length) {
      keptCountermeasures.push(countermeasure)
    } else {
      keptCountermeasures.push({ ...countermeasure, threatIds, targets })
    }
  }
  return {
    threats: keptThreats,
    countermeasures: keptCountermeasures,
    removedThreatIds,
    removedCountermeasureIds,
  }
}

/** Remove threats by id; countermeasures lose the link and go when they have no threat left. */
export function removeThreats(
  threats: GuestThreat[],
  countermeasures: GuestCountermeasure[],
  threatIds: ReadonlySet<string>
): RemovalResult {
  const removedThreatIds = threats.filter((threat) => threatIds.has(threat.id)).map((threat) => threat.id)
  const removedCountermeasureIds: string[] = []
  const keptCountermeasures: GuestCountermeasure[] = []
  for (const countermeasure of countermeasures) {
    const remaining = countermeasure.threatIds.filter((threatId) => !threatIds.has(threatId))
    if (remaining.length === 0 && countermeasure.threatIds.length > 0) {
      removedCountermeasureIds.push(countermeasure.id)
    } else if (remaining.length === countermeasure.threatIds.length) {
      keptCountermeasures.push(countermeasure)
    } else {
      keptCountermeasures.push({ ...countermeasure, threatIds: remaining })
    }
  }
  return {
    threats: threats.filter((threat) => !threatIds.has(threat.id)),
    countermeasures: keptCountermeasures,
    removedThreatIds,
    removedCountermeasureIds,
  }
}

// ---------------------------------------------------------------------------
// Derived statuses
// ---------------------------------------------------------------------------

export type DerivedThreatStatus = 'exposed' | 'addressable' | 'mitigated'

const SPEC_TO_OURS: Record<string, string> = {
  ...Object.fromEntries(Object.entries(COUNTERMEASURE_STATUS_TO_SPEC).map(([ours, spec]) => [spec, ours])),
  recommended: 'planned',
  proposed: 'planned',
  approved: 'planned',
  rejected: 'waived',
}

/** The backend's status for a control status as the file carries it. */
export function countermeasureBackendStatus(fileStatus: unknown): string {
  const name = typeof fileStatus === 'string'
    ? fileStatus
    : fileStatus && typeof fileStatus === 'object'
      ? String((fileStatus as { name?: unknown }).name ?? '')
      : ''
  if ((CUSTOM_COUNTERMEASURE_STATUSES as readonly string[]).includes(name)) return name
  return SPEC_TO_OURS[name] ?? 'gap'
}

/** The control status a guest-created countermeasure is written with. */
export const NEW_COUNTERMEASURE_STATUS = 'recommended'

export function countermeasureFileStatus(countermeasure: GuestCountermeasure): unknown {
  return countermeasure.passthrough?.status ?? NEW_COUNTERMEASURE_STATUS
}

export function deriveThreatStatus(
  threat: GuestThreat,
  countermeasures: readonly GuestCountermeasure[]
): DerivedThreatStatus {
  const statuses = countermeasures
    .filter((countermeasure) => countermeasure.threatIds.includes(threat.id))
    .map((countermeasure) => countermeasureBackendStatus(countermeasureFileStatus(countermeasure)))
  if (statuses.length === 0 || statuses.includes('gap')) return 'exposed'
  if (statuses.some((status) => ['planned', 'waived', 'in_progress', 'decommissioned'].includes(status))) {
    return 'addressable'
  }
  return 'mitigated'
}

// ---------------------------------------------------------------------------
// Diagram element lookups
// ---------------------------------------------------------------------------

export const TARGET_NODE_TYPES = new Set(['process', 'datastore', 'humanActor', 'systemActor', 'systemScope'])

export function targetTypeForNode(node: Pick<DiagramNode, 'type'>): GuestTargetType | null {
  if (node.type === 'trustZone') return 'zone'
  if (node.type && TARGET_NODE_TYPES.has(node.type)) return 'component'
  return null
}

export function targetTypeForEdge(edge: Pick<DiagramEdge, 'type'>): GuestTargetType | null {
  if (edge.type === 'dataFlow') return 'flow'
  if (edge.type === 'trustBoundary') return 'boundary'
  return null
}

/** The label the UI shows for a target; flows without a label read "source to destination". */
export function targetLabel(target: GuestTargetRef, nodes: readonly DiagramNode[], edges: readonly DiagramEdge[]): string {
  if (target.type === 'component' || target.type === 'zone') {
    const node = nodes.find((candidate) => candidate.id === target.id)
    return node ? String(node.data?.label || node.type || target.id) : target.id
  }
  const edge = edges.find((candidate) => candidate.id === target.id)
  if (!edge) return target.id
  const explicit = typeof edge.data?.label === 'string' ? edge.data.label : ''
  if (explicit) return explicit
  const labelOf = (nodeId: string) => {
    const node = nodes.find((candidate) => candidate.id === nodeId)
    return node ? String(node.data?.label || node.type || nodeId) : nodeId
  }
  return `${labelOf(edge.source)} to ${labelOf(edge.target)}`
}
