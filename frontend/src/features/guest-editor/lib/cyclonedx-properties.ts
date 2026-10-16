/**
 * `precogly:` properties as the backend registry defines them (plan 9.6).
 *
 * Values are encoded by the registered type: integers and booleans as their
 * string form, JSON as compact JSON with sorted keys, exactly as
 * `tmbom/properties.py` writes them. `mergeProperties` writes known values
 * back in the position the file had them, so a round trip keeps the order.
 */

import { PRECOGLY_PROPERTIES, PROPERTY_PREFIX } from './cyclonedx-spec.generated'
import type { CycloneDxProperty } from './cyclonedx-types'

export type PropertyValueType = 'string' | 'integer' | 'boolean' | 'date' | 'json'

const VALUE_TYPES = new Map<string, PropertyValueType>()
for (const entry of PRECOGLY_PROPERTIES) {
  VALUE_TYPES.set(`${entry.owner}\u0000${entry.name}`, entry.valueType as PropertyValueType)
}

/** The registered value type of a property for an owner, or null when unregistered. */
export function propertyValueType(owner: string, name: string): PropertyValueType | null {
  return VALUE_TYPES.get(`${owner}\u0000${name}`) ?? null
}

export function isPrecoglyProperty(name: string): boolean {
  return name.startsWith(PROPERTY_PREFIX)
}

/** JSON with sorted object keys and no whitespace, as Python's `json.dumps(sort_keys=True, separators=(",", ":"))`. */
export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function encodePropertyValue(value: unknown, valueType: PropertyValueType): string {
  if (valueType === 'json') return stableStringify(value)
  if (valueType === 'boolean') return value ? 'true' : 'false'
  return String(value)
}

export function decodePropertyValue(raw: string | undefined, valueType: PropertyValueType): unknown {
  const text = raw ?? ''
  if (valueType === 'json') {
    try {
      return JSON.parse(text)
    } catch {
      return undefined
    }
  }
  if (valueType === 'boolean') return ['true', '1', 'yes'].includes(text.trim().toLowerCase())
  if (valueType === 'integer') {
    const number = Number.parseInt(text, 10)
    return Number.isNaN(number) ? undefined : number
  }
  return text
}

/**
 * Registered properties of an object decoded by name. A name registered for
 * another owner is ignored, as the backend's `read_properties` does. A JSON
 * property that appears several times yields a list of every value.
 */
export function readProperties(
  properties: unknown,
  owner: string
): Map<string, unknown> {
  const decoded = new Map<string, unknown>()
  if (!Array.isArray(properties)) return decoded
  for (const item of properties) {
    if (!item || typeof item !== 'object') continue
    const name = (item as CycloneDxProperty).name
    if (typeof name !== 'string') continue
    const valueType = propertyValueType(owner, name)
    if (valueType === null) continue
    const rawValue = (item as CycloneDxProperty).value
    const value = decodePropertyValue(typeof rawValue === 'string' ? rawValue : '', valueType)
    if (value === undefined) continue
    if (valueType === 'json') {
      const existing = decoded.get(name)
      decoded.set(name, Array.isArray(existing) ? [...existing, value] : [value])
    } else {
      decoded.set(name, value)
    }
  }
  return decoded
}

/** A JSON property decoded to a flat list (a list value is spread, as the backend's `_flatten`). */
export function jsonPropertyItems(decoded: Map<string, unknown>, name: string): unknown[] {
  const values = decoded.get(name)
  if (!Array.isArray(values)) return []
  const result: unknown[] = []
  for (const value of values) {
    if (Array.isArray(value)) result.push(...value)
    else result.push(value)
  }
  return result
}

export interface KnownProperty {
  name: string
  /** Undefined removes the property when the file had it. */
  value: unknown
  valueType: PropertyValueType
}

/**
 * The property list to write: the file's list with every known name replaced
 * by its current value in place (or removed when the value is undefined),
 * then the known names the file did not have, appended in the given order.
 * Unknown properties (other tools', or registered ones the guest editor does
 * not model) stay where they were.
 */
export function mergeProperties(
  kept: readonly CycloneDxProperty[] | undefined,
  known: readonly KnownProperty[]
): CycloneDxProperty[] {
  const byName = new Map(known.map((entry) => [entry.name, entry]))
  const written = new Set<string>()
  const result: CycloneDxProperty[] = []
  for (const item of kept ?? []) {
    if (!item || typeof item !== 'object' || typeof item.name !== 'string') continue
    const entry = byName.get(item.name)
    if (entry === undefined) {
      result.push({ ...item })
      continue
    }
    if (written.has(item.name)) continue
    written.add(item.name)
    if (entry.value !== undefined) {
      result.push({ name: entry.name, value: encodePropertyValue(entry.value, entry.valueType) })
    }
  }
  for (const entry of known) {
    if (written.has(entry.name) || entry.value === undefined) continue
    written.add(entry.name)
    result.push({ name: entry.name, value: encodePropertyValue(entry.value, entry.valueType) })
  }
  return result
}

/** Shorthand for a known property whose type comes from the registry. */
export function known(owner: string, name: string, value: unknown): KnownProperty {
  const valueType = propertyValueType(owner, name)
  if (valueType === null) {
    throw new Error(`${name} is not registered for ${owner}`)
  }
  return { name, value, valueType }
}
