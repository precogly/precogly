/**
 * The elements a threat or control can sit on, and the wording for targets a
 * file names that are not on this diagram (plan 11.9, G8).
 */

import { ArrowRight, Box, Building2, Cog, Database, Shield, ShieldCheck, User } from 'lucide-react'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type { GuestTargetRef, GuestTargetType } from '../types'
import { targetLabel, targetTypeForEdge, targetTypeForNode } from './guest-model'

export interface TargetOption {
  ref: GuestTargetRef
  label: string
  group: string
  icon: typeof Cog
}

const GROUP_ORDER: Record<GuestTargetType, number> = { component: 0, flow: 1, zone: 2, boundary: 3 }
const GROUP_LABELS: Record<GuestTargetType, string> = {
  component: 'Components',
  flow: 'Flows',
  zone: 'Zones',
  boundary: 'Boundaries',
}

function iconForNode(node: DiagramNode): typeof Cog {
  switch (node.type) {
    case 'datastore':
      return Database
    case 'humanActor':
      return User
    case 'systemActor':
      return Building2
    case 'systemScope':
      return Box
    case 'trustZone':
      return Shield
    default:
      return Cog
  }
}

/** Every element of the diagram a threat or control can sit on, grouped by kind. */
export function targetOptions(nodes: readonly DiagramNode[], edges: readonly DiagramEdge[]): TargetOption[] {
  const options: TargetOption[] = []
  for (const node of nodes) {
    const type = targetTypeForNode(node)
    if (!type) continue
    const ref = { id: node.id, type }
    options.push({ ref, label: targetLabel(ref, nodes, edges), group: GROUP_LABELS[type], icon: iconForNode(node) })
  }
  for (const edge of edges) {
    const type = targetTypeForEdge(edge)
    if (!type) continue
    const ref = { id: edge.id, type }
    options.push({ ref, label: targetLabel(ref, nodes, edges), group: GROUP_LABELS[type], icon: type === 'flow' ? ArrowRight : ShieldCheck })
  }
  return options.sort((left, right) => GROUP_ORDER[left.ref.type] - GROUP_ORDER[right.ref.type])
}

/** The sentence shown beside a threat for targets the file names that are not on this diagram. */
export function hiddenTargetsNote(hiddenRefs: readonly string[], hiddenBlueprintTargetCount: number): string | null {
  if (hiddenRefs.length === 0) return null
  const elsewhere = hiddenRefs.length - hiddenBlueprintTargetCount
  const parts: string[] = []
  if (hiddenBlueprintTargetCount > 0) {
    parts.push(`also targets ${hiddenBlueprintTargetCount} element${hiddenBlueprintTargetCount === 1 ? '' : 's'} in another blueprint`)
  }
  if (elsewhere > 0) {
    parts.push(`also targets ${elsewhere} element${elsewhere === 1 ? '' : 's'} not on the diagram`)
  }
  return parts.join('; ')
}
