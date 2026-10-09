/**
 * The DFD canvas inside a TM-BOM visualization attachment (plan 9.4, G5).
 *
 * The backend stores canvases with snake_case keys (its camel-case request
 * parser rewrites them on the way in) and writes them out as they are, base64
 * encoded under `application/vnd.precogly.dfd+json`. The guest editor keeps
 * React Flow's camelCase in memory and converts at the file boundary, so a
 * file written here reads the same in the signed-in app and back.
 */

import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'

/** React Flow and editor flags that describe a moment, not the diagram. */
const TRANSIENT_NODE_KEYS = new Set(['selected', 'dragging', 'extent'])
const TRANSIENT_DATA_KEYS = new Set(['isInlineEditing', 'isNewlyInserted', 'lockAnimationKey', 'receiveChildAnimationKey'])

export function snakeCaseKey(key: string): string {
  return key.replace(/([A-Z])/g, (letter) => `_${letter.toLowerCase()}`)
}

export function camelCaseKey(key: string): string {
  return key.replace(/_([a-z0-9])/g, (_match, letter: string) => letter.toUpperCase())
}

function convertKeys(value: unknown, convert: (key: string) => string): unknown {
  if (Array.isArray(value)) return value.map((item) => convertKeys(item, convert))
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      result[convert(key)] = convertKeys(item, convert)
    }
    return result
  }
  return value
}

export function keysToSnakeCase(value: unknown): unknown {
  return convertKeys(value, snakeCaseKey)
}

export function keysToCamelCase(value: unknown): unknown {
  return convertKeys(value, camelCaseKey)
}

/** A node as written to the file: transient flags dropped, keys in snake_case. */
export function nodeForFile(node: DiagramNode, bomRef: string | null): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(node)) {
    if (TRANSIENT_NODE_KEYS.has(key) || value === undefined) continue
    cleaned[key] = value
  }
  const data: Record<string, unknown> = {}
  for (const [key, value] of Object.entries((node.data ?? {}) as Record<string, unknown>)) {
    if (TRANSIENT_DATA_KEYS.has(key) || value === undefined) continue
    data[key] = value
  }
  if (bomRef) data.bomRef = bomRef
  else delete data.bomRef
  cleaned.data = data
  return keysToSnakeCase(cleaned) as Record<string, unknown>
}

export function edgeForFile(edge: DiagramEdge, bomRef: string | null): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(edge)) {
    if (TRANSIENT_NODE_KEYS.has(key) || value === undefined) continue
    cleaned[key] = value
  }
  const data: Record<string, unknown> = {}
  for (const [key, value] of Object.entries((edge.data ?? {}) as Record<string, unknown>)) {
    if (TRANSIENT_DATA_KEYS.has(key) || value === undefined) continue
    data[key] = value
  }
  if (bomRef) data.bomRef = bomRef
  else delete data.bomRef
  cleaned.data = data
  return keysToSnakeCase(cleaned) as Record<string, unknown>
}

function utf8ToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function base64ToUtf8(encoded: string): string {
  const binary = atob(encoded)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return new TextDecoder().decode(bytes)
}

/** Compact JSON (`json.dumps(separators=(",", ":"))`) as base64, the attachment's content. */
export function encodeCanvasContent(canvas: Record<string, unknown>): string {
  return utf8ToBase64(JSON.stringify(canvas))
}

/** The parsed canvas of an attachment, or null when it does not decode. */
export function decodeCanvasContent(content: unknown, encoding: unknown): Record<string, unknown> | null {
  if (typeof content !== 'string') return null
  try {
    const text = encoding === 'base64' ? base64ToUtf8(content) : content
    const parsed: unknown = JSON.parse(text)
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}
