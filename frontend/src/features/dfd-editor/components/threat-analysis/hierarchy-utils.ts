/**
 * The analysis tree (plan 11.3): a "System" root holding the whole-system
 * threats, a blueprint level only when the model has more than one, zones
 * nested by parent with their components (components nested by parent
 * component) and their zone-scoped threats, components in no zone, and a
 * "Flows" and a "Boundaries" group per blueprint.
 *
 * A threat with several targets appears under each target; counts use a set
 * of threat ids, so each scenario counts once at every level. Built from the
 * backend rows, not the canvas, so targets off any canvas are listed too.
 */

import type { ZoneType } from '@/types/domain'
import type { AnalysisThreat, TargetType } from '../../types/threat-analysis'
import { deriveThreatStatus } from '../../types/threat-analysis'
import { isActiveThreat } from '@/types/triage'
import { SYSTEM_SELECTION, targetSelection, type AnalysisSelection } from './analysis-selection'

export type AnalysisTreeNodeKind =
  | 'system'
  | 'blueprint'
  | 'zone'
  | 'component'
  | 'flow'
  | 'boundary'
  | 'flowsGroup'
  | 'boundariesGroup'

export interface AnalysisTreeCounts {
  total: number
  exposed: number
  addressable: number
  mitigated: number
}

export interface AnalysisTreeNode {
  /** Unique within the tree: `system`, `blueprint-1`, `zone-3`, `flows-1`. */
  key: string
  kind: AnalysisTreeNodeKind
  label: string
  secondaryLabel?: string
  /** What selecting the row selects; null for a group row. */
  selection: AnalysisSelection | null
  children: AnalysisTreeNode[]
  depth: number
  /** Ids of the active threats placed directly on this row's target. */
  directThreatIds: Set<string>
  /** Ids of the active threats in this row's subtree, each once. */
  subtreeThreatIds: Set<string>
  counts: AnalysisTreeCounts
  backendId?: number
  blueprintId?: number
  zoneType?: ZoneType
  trustLevel?: number | null
  category?: string
  /** A component created in the analysis screen, deletable from there. */
  isAnalysisOnly?: boolean
}

export interface AnalysisTreeBlueprint {
  id: number
  name: string
  displayOrder?: number
}

export interface AnalysisTreeComponent {
  id: number
  name: string
  blueprint: number
  zone: number | null
  parentComponent: number | null
  category?: string
  componentLibraryName?: string | null
  /** Not on any canvas (the analysis payload's node map says so). */
  isAnalysisOnly?: boolean
}

export interface AnalysisTreeZone {
  id: number
  name: string
  blueprint: number
  parent: number | null
  zoneType?: ZoneType
  trustLevel?: number | null
}

export interface AnalysisTreeFlow {
  id: number
  blueprint: number
  label: string
  sourceComponentName?: string
  destComponentName?: string
}

export interface AnalysisTreeBoundary {
  id: number
  blueprint: number
  label: string
  zoneAName?: string
  zoneBName?: string
}

export interface AnalysisTreeInput {
  blueprints: AnalysisTreeBlueprint[]
  components: AnalysisTreeComponent[]
  zones: AnalysisTreeZone[]
  flows: AnalysisTreeFlow[]
  boundaries: AnalysisTreeBoundary[]
  threats: AnalysisThreat[]
}

export interface AnalysisTree {
  root: AnalysisTreeNode
  /** Every row by key, for lookups from a selection. */
  byKey: Map<string, AnalysisTreeNode>
}

function makeNode(
  key: string,
  kind: AnalysisTreeNodeKind,
  label: string,
  selection: AnalysisSelection | null,
  extra: Partial<AnalysisTreeNode> = {}
): AnalysisTreeNode {
  return {
    key,
    kind,
    label,
    selection,
    children: [],
    depth: 0,
    directThreatIds: new Set(),
    subtreeThreatIds: new Set(),
    counts: { total: 0, exposed: 0, addressable: 0, mitigated: 0 },
    ...extra,
  }
}

export function flowLabel(flow: Pick<AnalysisTreeFlow, 'label' | 'sourceComponentName' | 'destComponentName'>): string {
  if (flow.label) return flow.label
  if (flow.sourceComponentName || flow.destComponentName) {
    return `${flow.sourceComponentName ?? '?'} to ${flow.destComponentName ?? '?'}`
  }
  return 'Flow'
}

export function boundaryLabel(
  boundary: Pick<AnalysisTreeBoundary, 'label' | 'zoneAName' | 'zoneBName'>
): string {
  if (boundary.label) return boundary.label
  if (boundary.zoneAName || boundary.zoneBName) {
    return `${boundary.zoneAName ?? '?'} | ${boundary.zoneBName ?? '?'}`
  }
  return 'Boundary'
}

/** The active threats indexed by target key (`component:5`) and `system`. */
function indexThreats(threats: AnalysisThreat[]): Map<string, AnalysisThreat[]> {
  const index = new Map<string, AnalysisThreat[]>()
  const push = (key: string, threat: AnalysisThreat) => {
    const list = index.get(key)
    if (list) list.push(threat)
    else index.set(key, [threat])
  }
  for (const threat of threats) {
    if (!isActiveThreat(threat.triageStatus)) continue
    if (threat.wholeSystem) {
      push('system', threat)
      continue
    }
    for (const target of threat.targets) push(`${target.type}:${target.id}`, threat)
  }
  return index
}

function countThreats(ids: Set<string>, threatsById: Map<string, AnalysisThreat>): AnalysisTreeCounts {
  const counts: AnalysisTreeCounts = { total: 0, exposed: 0, addressable: 0, mitigated: 0 }
  for (const id of ids) {
    const threat = threatsById.get(id)
    if (!threat) continue
    counts.total += 1
    const status = deriveThreatStatus(threat.countermeasures)
    if (status === 'exposed') counts.exposed += 1
    else if (status === 'addressable') counts.addressable += 1
    else counts.mitigated += 1
  }
  return counts
}

/**
 * Build the tree. `threats` may include triaged scenarios; only active ones
 * count (as the old per-component summary did).
 */
export function buildAnalysisTree(input: AnalysisTreeInput): AnalysisTree {
  const threatIndex = indexThreats(input.threats)
  const threatsById = new Map(input.threats.map((threat) => [threat.id, threat]))
  const byKey = new Map<string, AnalysisTreeNode>()

  const directIds = (targetType: TargetType | 'system', id?: number): Set<string> => {
    const key = targetType === 'system' ? 'system' : `${targetType}:${id}`
    return new Set((threatIndex.get(key) ?? []).map((threat) => threat.id))
  }

  const componentsById = new Map(input.components.map((component) => [component.id, component]))
  const zonesById = new Map(input.zones.map((zone) => [zone.id, zone]))

  // A component nests under its parent component when that parent exists in
  // the model; a parent chain that loops is cut at the first repeat.
  const childComponents = new Map<number, AnalysisTreeComponent[]>()
  const topLevelComponents: AnalysisTreeComponent[] = []
  for (const component of input.components) {
    const parentId = component.parentComponent
    if (parentId !== null && componentsById.has(parentId) && parentId !== component.id) {
      const siblings = childComponents.get(parentId) ?? []
      siblings.push(component)
      childComponents.set(parentId, siblings)
    } else {
      topLevelComponents.push(component)
    }
  }

  const childZones = new Map<number, AnalysisTreeZone[]>()
  const topLevelZones: AnalysisTreeZone[] = []
  for (const zone of input.zones) {
    const parentId = zone.parent
    if (parentId !== null && zonesById.has(parentId) && parentId !== zone.id) {
      const siblings = childZones.get(parentId) ?? []
      siblings.push(zone)
      childZones.set(parentId, siblings)
    } else {
      topLevelZones.push(zone)
    }
  }

  const byName = <T extends { name: string }>(rows: T[]) =>
    [...rows].sort((left, right) => left.name.localeCompare(right.name))

  // Rows placed so far, so a parent cycle (which has no top-level row) still
  // ends up in the tree, under its blueprint.
  const placedComponents = new Set<number>()
  const placedZones = new Set<number>()

  const buildComponentNode = (component: AnalysisTreeComponent, visited: Set<number>): AnalysisTreeNode | null => {
    if (visited.has(component.id) || placedComponents.has(component.id)) return null
    const nextVisited = new Set(visited).add(component.id)
    placedComponents.add(component.id)
    const node = makeNode(
      `component-${component.id}`,
      'component',
      component.name,
      targetSelection('component', component.id),
      {
        secondaryLabel: component.componentLibraryName ?? undefined,
        backendId: component.id,
        blueprintId: component.blueprint,
        category: component.category,
        isAnalysisOnly: component.isAnalysisOnly,
        directThreatIds: directIds('component', component.id),
      }
    )
    for (const child of byName(childComponents.get(component.id) ?? [])) {
      const childNode = buildComponentNode(child, nextVisited)
      if (childNode) node.children.push(childNode)
    }
    return node
  }

  const buildZoneNode = (zone: AnalysisTreeZone, visited: Set<number>): AnalysisTreeNode | null => {
    if (visited.has(zone.id) || placedZones.has(zone.id)) return null
    const nextVisited = new Set(visited).add(zone.id)
    placedZones.add(zone.id)
    const node = makeNode(`zone-${zone.id}`, 'zone', zone.name, targetSelection('zone', zone.id), {
      backendId: zone.id,
      blueprintId: zone.blueprint,
      zoneType: zone.zoneType,
      trustLevel: zone.trustLevel ?? null,
      directThreatIds: directIds('zone', zone.id),
    })
    for (const child of byName(childZones.get(zone.id) ?? [])) {
      const childNode = buildZoneNode(child, nextVisited)
      if (childNode) node.children.push(childNode)
    }
    for (const component of byName(topLevelComponents.filter((row) => row.zone === zone.id))) {
      const componentNode = buildComponentNode(component, new Set())
      if (componentNode) node.children.push(componentNode)
    }
    return node
  }

  const buildBlueprintContent = (blueprintId: number, into: AnalysisTreeNode) => {
    for (const zone of byName(topLevelZones.filter((row) => row.blueprint === blueprintId))) {
      const zoneNode = buildZoneNode(zone, new Set())
      if (zoneNode) into.children.push(zoneNode)
    }
    const unzoned = topLevelComponents.filter(
      (row) => row.blueprint === blueprintId && (row.zone === null || !zonesById.has(row.zone))
    )
    for (const component of byName(unzoned)) {
      const componentNode = buildComponentNode(component, new Set())
      if (componentNode) into.children.push(componentNode)
    }
    // Leftovers: rows whose parent chain never reaches a top-level row.
    for (const zone of byName(input.zones.filter((row) => row.blueprint === blueprintId && !placedZones.has(row.id)))) {
      const zoneNode = buildZoneNode(zone, new Set())
      if (zoneNode) into.children.push(zoneNode)
    }
    for (const component of byName(
      input.components.filter((row) => row.blueprint === blueprintId && !placedComponents.has(row.id))
    )) {
      const componentNode = buildComponentNode(component, new Set())
      if (componentNode) into.children.push(componentNode)
    }

    const flows = input.flows.filter((row) => row.blueprint === blueprintId)
    if (flows.length > 0) {
      const group = makeNode(`flows-${blueprintId}`, 'flowsGroup', 'Flows', null, { blueprintId })
      for (const flow of flows) {
        group.children.push(
          makeNode(`flow-${flow.id}`, 'flow', flowLabel(flow), targetSelection('flow', flow.id), {
            secondaryLabel:
              flow.label && (flow.sourceComponentName || flow.destComponentName)
                ? `${flow.sourceComponentName ?? '?'} to ${flow.destComponentName ?? '?'}`
                : undefined,
            backendId: flow.id,
            blueprintId,
            directThreatIds: directIds('flow', flow.id),
          })
        )
      }
      into.children.push(group)
    }

    const boundaries = input.boundaries.filter((row) => row.blueprint === blueprintId)
    if (boundaries.length > 0) {
      const group = makeNode(`boundaries-${blueprintId}`, 'boundariesGroup', 'Boundaries', null, { blueprintId })
      for (const boundary of boundaries) {
        group.children.push(
          makeNode(
            `boundary-${boundary.id}`,
            'boundary',
            boundaryLabel(boundary),
            targetSelection('boundary', boundary.id),
            {
              secondaryLabel:
                boundary.label && (boundary.zoneAName || boundary.zoneBName)
                  ? `${boundary.zoneAName ?? '?'} | ${boundary.zoneBName ?? '?'}`
                  : undefined,
              backendId: boundary.id,
              blueprintId,
              directThreatIds: directIds('boundary', boundary.id),
            }
          )
        )
      }
      into.children.push(group)
    }
  }

  const root = makeNode('system', 'system', 'System', SYSTEM_SELECTION, {
    directThreatIds: directIds('system'),
  })

  const blueprints = [...input.blueprints].sort(
    (left, right) => (left.displayOrder ?? 0) - (right.displayOrder ?? 0) || left.id - right.id
  )
  if (blueprints.length > 1) {
    for (const blueprint of blueprints) {
      const blueprintNode = makeNode(`blueprint-${blueprint.id}`, 'blueprint', blueprint.name, null, {
        backendId: blueprint.id,
        blueprintId: blueprint.id,
      })
      buildBlueprintContent(blueprint.id, blueprintNode)
      root.children.push(blueprintNode)
    }
  } else {
    const onlyBlueprintId = blueprints[0]?.id
    const blueprintIds = new Set<number>()
    if (onlyBlueprintId !== undefined) blueprintIds.add(onlyBlueprintId)
    // Rows of a blueprint the model list does not name still show, so nothing
    // disappears when the blueprint list and the rows disagree.
    for (const row of [...input.components, ...input.zones, ...input.flows, ...input.boundaries]) {
      blueprintIds.add(row.blueprint)
    }
    for (const blueprintId of blueprintIds) buildBlueprintContent(blueprintId, root)
  }

  // Depths, subtree sets and counts in one pass. The root counts only its
  // own whole-system threats (the mockup's "System (2)"); every other row
  // counts its subtree, each scenario once.
  const finish = (node: AnalysisTreeNode, depth: number) => {
    node.depth = depth
    const subtree = new Set(node.directThreatIds)
    for (const child of node.children) {
      finish(child, depth + 1)
      for (const id of child.subtreeThreatIds) subtree.add(id)
    }
    node.subtreeThreatIds = subtree
    node.counts = countThreats(node.kind === 'system' ? node.directThreatIds : subtree, threatsById)
    byKey.set(node.key, node)
  }
  finish(root, 0)

  return { root, byKey }
}
