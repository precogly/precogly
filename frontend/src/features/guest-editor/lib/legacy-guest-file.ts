/**
 * Files saved by the guest editor before the CycloneDX 2.0 alignment (#584).
 *
 * The earlier guest editor wrote the whole canvas and the system context
 * (session, criticality, data asset ratings, out-of-scope items) into one
 * `precogly-dfd` visualization under `data`, linked a scenario to its threat
 * with `threat`, and used its own names for statuses, STRIDE categories and
 * assumption validity. Guest users have no database behind them, so their
 * files are their only copy: this module rewrites such a file into the
 * current shape before the importer reads it, and hands back the system
 * context for `applyLegacySystemContext` to fill in afterwards. Saving the
 * file again writes the current format.
 */

import type { GuestSystemContext } from '../types'
import { DATA_CLASSIFICATIONS, THREAT_CATEGORIES } from './cyclonedx-spec.generated'

type JsonObject = Record<string, unknown>

/** The visualization type the earlier guest editor wrote its canvas under. */
export const LEGACY_VISUALIZATION_TYPE = 'precogly-dfd'

export const LEGACY_FILE_WARNING =
  'This file was saved by an earlier version of the guest editor and was converted on opening. Save it to write the current CycloneDX 2.0 format.'

const LEGACY_VALIDITY: Record<string, string> = {
  confirmed: 'verified',
  rejected: 'invalid',
  unconfirmed: 'unverified',
}

const STRIDE_CATEGORIES = new Set<string>(THREAT_CATEGORIES.STRIDE)
const CLASSIFICATIONS = new Set<string>(DATA_CLASSIFICATIONS)
const RATINGS = new Set(['low', 'medium', 'high'])
const CRITICALITIES = new Set(['low', 'medium', 'high', 'critical'])

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function objects(value: unknown): JsonObject[] {
  return Array.isArray(value) ? value.filter(isObject) : []
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/** The earlier guest editor's canvas visualization in the first blueprint, if there is one. */
export function legacyVisualization(blueprint: unknown): JsonObject | null {
  if (!isObject(blueprint)) return null
  return objects(blueprint.visualizations).find(
    (visualization) => visualization.type === LEGACY_VISUALIZATION_TYPE && isObject(visualization.data)
  ) ?? null
}

/**
 * Rewrite a file from the earlier guest editor in place. Returns its system
 * context (possibly empty), or null when the file is not in the old format.
 */
export function upgradeLegacyGuestFile(document: JsonObject): JsonObject | null {
  const blueprint = objects(document.blueprints)[0]
  const visualization = legacyVisualization(blueprint)
  if (!blueprint || !visualization) return null

  for (const zone of objects(blueprint.zones)) {
    if (typeof zone.trustLevel === 'number') {
      zone.properties = [...objects(zone.properties), { name: 'precogly:trust-level', value: String(zone.trustLevel) }]
    }
    delete zone.trustLevel
  }
  // Data stores were assets of type data-store; the spec lists them apart, with their own types.
  const assets = objects(blueprint.assets)
  const dataStores = assets.filter((asset) => asset.type === 'data-store')
  if (dataStores.length > 0) {
    for (const dataStore of dataStores) delete dataStore.type
    blueprint.assets = assets.filter((asset) => !dataStores.includes(asset))
    blueprint.dataStores = [...objects(blueprint.dataStores), ...dataStores]
  }
  // The canvas edge keeps the authenticated flag; the spec has no such field on a flow.
  for (const flow of objects(blueprint.flows)) delete flow.authenticated
  // The classification comes back from the system context, with the ratings.
  for (const dataSet of objects(blueprint.dataSets)) delete dataSet.classification
  for (const assumption of objects(blueprint.assumptions)) {
    const validity = LEGACY_VALIDITY[text(assumption.validity)]
    if (validity) assumption.validity = validity
  }

  const threatsSection = isObject(document.threats) ? document.threats : {}
  for (const threat of objects(threatsSection.threats)) {
    const stride = objects(threat.categories).find((category) => text(category.taxonomy).toLowerCase() === 'stride')
    const category = text(stride?.id)
    if (STRIDE_CATEGORIES.has(category)) threat.categories = [{ taxonomy: 'STRIDE', category }]
    else delete threat.categories
  }
  for (const scenario of objects(threatsSection.scenarios)) {
    if (typeof scenario.threat === 'string' && !Array.isArray(scenario.threats)) scenario.threats = [scenario.threat]
    delete scenario.threat
    // The earlier editor stored the triage decision as the threat status.
    for (const property of objects(scenario.properties)) {
      if (property.name === 'precogly:threat-status') property.name = 'precogly:triage-status'
    }
  }

  // The same link is on the threat's `mitigations`; the spec has no such field on a control.
  for (const control of objects(document.controls)) delete control.mitigations

  const data = isObject(visualization.data) ? visualization.data : {}
  return isObject(data.systemContext) ? data.systemContext : {}
}

/** The canvas the earlier guest editor kept under the visualization's `data`, in the current canvas shape. */
export function legacyCanvas(visualization: JsonObject): JsonObject {
  const data = isObject(visualization.data) ? visualization.data : {}
  const canvas: JsonObject = {
    nodes: Array.isArray(data.nodes) ? data.nodes : [],
    edges: Array.isArray(data.edges) ? data.edges : [],
  }
  if (typeof data.notationStyle === 'string') canvas.notation_style = data.notationStyle
  return canvas
}

/** Fill what the file's current fields could not carry from the earlier editor's system context. */
export function applyLegacySystemContext(target: GuestSystemContext, legacy: JsonObject): void {
  const session = isObject(legacy.session) ? legacy.session : {}
  if (!target.session.facilitator && !target.session.meetingDate && target.session.participants.length === 0) {
    target.session = {
      facilitator: text(session.facilitator),
      participants: strings(session.participants),
      meetingDate: text(session.meetingDate),
    }
  }

  const systemInfo = isObject(legacy.systemInfo) ? legacy.systemInfo : {}
  const criticality = text(systemInfo.criticality)
  if (CRITICALITIES.has(criticality)) {
    target.systemInfo.criticality = criticality as GuestSystemContext['systemInfo']['criticality']
  }
  if (!target.systemInfo.description) target.systemInfo.description = text(systemInfo.description)

  if (target.outOfScopeItems.length === 0) {
    target.outOfScopeItems = objects(legacy.outOfScopeItems)
      .filter((item) => text(item.name))
      .map((item, position) => ({ id: text(item.id) || `out-of-scope-${position + 1}`, name: text(item.name), reason: text(item.reason) }))
  }

  const legacyAssets = new Map(objects(legacy.dataAssets).map((asset) => [text(asset.name), asset]))
  for (const asset of target.dataAssets) {
    const old = legacyAssets.get(asset.name)
    if (!old) continue
    if (!asset.classification && CLASSIFICATIONS.has(text(old.classification))) asset.classification = text(old.classification)
    for (const key of ['confidentiality', 'integrity', 'availability'] as const) {
      if (RATINGS.has(text(old[key]))) asset[key] = text(old[key]) as 'low' | 'medium' | 'high'
    }
    if (asset.complianceTags.length === 0) asset.complianceTags = strings(old.complianceTags)
    if (asset.dataSensitivity.length === 0) asset.dataSensitivity = strings(old.dataSensitivity)
  }
}
