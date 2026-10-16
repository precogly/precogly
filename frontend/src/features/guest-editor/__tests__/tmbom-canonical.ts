/**
 * A TypeScript port of `canonical()` from
 * `backend/apps/threat_models/tests/tmbom_reference.py`, so a guest editor
 * export can be compared with the shared fixture the same way two backend
 * exports are: refs become ordinal tokens in document order, serial number,
 * version, timestamps and dates are blanked, row ids inside the canvas are
 * stripped, and the review block with its party roles is dropped (import does
 * not approve, D18).
 *
 * One addition to the Python version: `metadata.tools` is blanked as well,
 * since the guest editor names itself as the tool and the backend names
 * Precogly; the tool entry is not content of the model.
 */

const DATE_KEYS = new Set(['timestamp', 'reviewDate', 'approvalDate', 'validationDate', 'targetDate'])
const REVIEW_KEYS = new Set(['reviewer', 'reviewDate', 'approver', 'approvalDate'])
const REVIEW_ROLES = new Set(['reviewer', 'signatory'])
const CANVAS_ID_KEYS = new Set(['component_id', 'trust_zone_id', 'dataflow_id', 'trust_boundary_id', 'orgsystem_id'])
const BOM_LINK = /^(urn:cdx:)[0-9a-f-]{36}\/\d+(#.*)?$/

type Json = unknown

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function sortedStringify(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(sortedStringify).join(',')}]`
  if (isObject(value)) {
    const keys = Object.keys(value).sort()
    return `{${keys.map((key) => `${JSON.stringify(key)}:${sortedStringify(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function decodeBase64Json(content: string): Json | null {
  try {
    const binary = atob(content)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

function stripCanvasIds(node: Json): Json {
  if (Array.isArray(node)) return node.map(stripCanvasIds)
  if (isObject(node)) {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(node)) {
      if (!CANVAS_ID_KEYS.has(key)) result[key] = stripCanvasIds(value)
    }
    return result
  }
  return node
}

export function canonical(document: Record<string, unknown>): Json {
  const doc: Record<string, unknown> = JSON.parse(JSON.stringify(document))
  delete doc.serialNumber
  delete doc.version
  if (isObject(doc.metadata) && 'tools' in doc.metadata) doc.metadata.tools = '<tools>'

  const refs = new Map<string, string>()
  const token = (value: string) => {
    if (!refs.has(value)) refs.set(value, `ref:${refs.size + 1}`)
    return refs.get(value)!
  }
  const collect = (node: Json) => {
    if (Array.isArray(node)) {
      for (const item of node) collect(item)
    } else if (isObject(node)) {
      if (typeof node['bom-ref'] === 'string') token(node['bom-ref'])
      for (const value of Object.values(node)) collect(value)
    }
  }
  collect(doc)

  const rewrite = (node: Json, key?: string): Json => {
    if (isObject(node)) {
      let current: Record<string, unknown> = node
      if (key === 'metadata' && Object.keys(current).some((candidate) => REVIEW_KEYS.has(candidate))) {
        current = Object.fromEntries(Object.entries(current).filter(([candidate]) => !REVIEW_KEYS.has(candidate)))
      }
      if (Array.isArray(current.roles)) {
        current = {
          ...current,
          roles: current.roles.filter((role) => !(isObject(role) && REVIEW_ROLES.has(String(role.role)))),
        }
      }
      if (key === 'attachment' && current.encoding === 'base64' && typeof current.content === 'string') {
        const decoded = decodeBase64Json(current.content)
        if (decoded !== null) current = { ...current, content: stripCanvasIds(decoded) }
      }
      return Object.fromEntries(Object.entries(current).map(([childKey, value]) => [childKey, rewrite(value, childKey)]))
    }
    if (Array.isArray(node)) {
      let items = node.map((item) => rewrite(item, key))
      if (key === 'parties') {
        items = items.filter((party) => !isObject(party) || (Array.isArray(party.roles) && party.roles.length > 0))
      }
      return items
    }
    if (typeof node === 'string') {
      if (key && DATE_KEYS.has(key)) return '<date>'
      if (refs.has(node)) return refs.get(node)
      const match = BOM_LINK.exec(node)
      if (match) return `urn:cdx:<serial>${match[2] ?? ''}`
      if (node.startsWith('urn:uuid:')) return 'urn:uuid:<serial>'
      if (key === 'value' && (node.startsWith('[') || node.startsWith('{'))) {
        try {
          return sortedStringify(rewrite(JSON.parse(node)))
        } catch {
          return node
        }
      }
      return node
    }
    return node
  }

  return rewrite(doc)
}

/** Canonical JSON as lines, so a failed comparison prints a readable diff. */
export function canonicalLines(document: Record<string, unknown>): string[] {
  return JSON.stringify(sortKeysDeep(canonical(document)), null, 1).split('\n')
}

function sortKeysDeep(value: Json): Json {
  if (Array.isArray(value)) return value.map(sortKeysDeep)
  if (isObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeysDeep(value[key])]))
  }
  return value
}
