/**
 * Pure helpers for blueprints (plan J2, J8): which blueprint is selected,
 * how rows are grouped by blueprint, and what a delete preview says.
 */

import type { Blueprint, BlueprintDeletePreview } from '@/features/threat-models/types/core'

/** Blueprints in display order, then by id so the order is stable. */
export function sortBlueprints(blueprints: Blueprint[]): Blueprint[] {
  return [...blueprints].sort(
    (first, second) => first.displayOrder - second.displayOrder || first.id - second.id
  )
}

/**
 * The blueprint the page should treat as selected: the requested one when
 * it still exists, else the first blueprint, else null (no blueprints yet).
 */
export function resolveSelectedBlueprintId(
  requestedBlueprintId: number | null | undefined,
  blueprints: Blueprint[]
): number | null {
  if (blueprints.length === 0) return null
  if (
    requestedBlueprintId != null &&
    blueprints.some((blueprint) => blueprint.id === requestedBlueprintId)
  ) {
    return requestedBlueprintId
  }
  return sortBlueprints(blueprints)[0].id
}

/** The blueprint select and the grouped lists appear only with more than one blueprint (J8). */
export function showsBlueprintChoice(blueprints: Blueprint[]): boolean {
  return blueprints.length > 1
}

export interface BlueprintGroup<T> {
  /** Null for rows whose blueprint is unknown to the model. */
  blueprint: Blueprint | null
  items: T[]
}

/**
 * Group rows by their `blueprint` key in blueprint display order. Rows that
 * carry no known blueprint land in one trailing group with `blueprint: null`.
 * Empty groups are left out.
 */
export function groupByBlueprint<T extends { blueprint?: number | null }>(
  items: T[],
  blueprints: Blueprint[]
): BlueprintGroup<T>[] {
  const groups: BlueprintGroup<T>[] = sortBlueprints(blueprints).map((blueprint) => ({
    blueprint,
    items: items.filter((item) => item.blueprint === blueprint.id),
  }))
  const knownIds = new Set(blueprints.map((blueprint) => blueprint.id))
  const unassigned = items.filter((item) => item.blueprint == null || !knownIds.has(item.blueprint))
  if (unassigned.length > 0) groups.push({ blueprint: null, items: unassigned })
  return groups.filter((group) => group.items.length > 0)
}

export function blueprintName(blueprintId: number | null | undefined, blueprints: Blueprint[]): string {
  return blueprints.find((blueprint) => blueprint.id === blueprintId)?.name ?? 'No blueprint'
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`
}

/**
 * The lines of the delete confirmation: what goes with the blueprint, then
 * the threats that are deleted. Zero counts are left out.
 */
export function deletePreviewLines(preview: BlueprintDeletePreview): string[] {
  const parts: string[] = []
  if (preview.components > 0) parts.push(plural(preview.components, 'component'))
  if (preview.flows > 0) parts.push(plural(preview.flows, 'flow'))
  if (preview.zones > 0) parts.push(plural(preview.zones, 'zone'))
  if (preview.boundaries > 0) parts.push(plural(preview.boundaries, 'boundary', 'boundaries'))
  if (preview.diagrams > 0) parts.push(plural(preview.diagrams, 'diagram'))
  if (preview.dataAssets > 0) parts.push(plural(preview.dataAssets, 'data asset'))
  if (preview.outOfScopeItems > 0) parts.push(plural(preview.outOfScopeItems, 'out-of-scope item'))
  const lines: string[] = []
  if (parts.length > 0) lines.push(parts.join(', '))
  if (preview.threatsDeleted > 0) {
    lines.push(`${plural(preview.threatsDeleted, 'threat')} that only sit on things in this blueprint`)
  }
  return lines
}

/** The next display order for a new blueprint: after the last one. */
export function nextDisplayOrder(blueprints: Blueprint[]): number {
  return blueprints.reduce((highest, blueprint) => Math.max(highest, blueprint.displayOrder), -1) + 1
}

/**
 * Swap the display order of the blueprint at `index` with its neighbour.
 * Returns the two updates to send, or an empty list at the edge.
 */
export function reorderBlueprints(
  blueprints: Blueprint[],
  index: number,
  direction: 'up' | 'down'
): Array<{ blueprintId: number; displayOrder: number }> {
  const ordered = sortBlueprints(blueprints)
  const neighbourIndex = direction === 'up' ? index - 1 : index + 1
  if (index < 0 || index >= ordered.length || neighbourIndex < 0 || neighbourIndex >= ordered.length) {
    return []
  }
  // Display orders may collide (several zeros after an import), so the whole
  // list is renumbered by position; only rows whose order changes are sent.
  const swapped = [...ordered]
  ;[swapped[index], swapped[neighbourIndex]] = [swapped[neighbourIndex], swapped[index]]
  return swapped
    .map((blueprint, position) => ({ blueprintId: blueprint.id, displayOrder: position, previous: blueprint.displayOrder }))
    .filter((update) => update.displayOrder !== update.previous)
    .map(({ blueprintId, displayOrder }) => ({ blueprintId, displayOrder }))
}
