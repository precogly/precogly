/**
 * The table view's search box (plan 11.3): matches a threat's name and its
 * number as `T7` (or a bare `7`). Several words all have to match.
 */

export interface ParsedThreatSearch {
  /** Numbers typed as `T7`, `t7` or `7`. */
  numbers: number[]
  /** The remaining words, lower-cased. */
  words: string[]
}

const NUMBER_TOKEN = /^t?(\d+)$/i

export function parseThreatSearch(raw: string): ParsedThreatSearch {
  const numbers: number[] = []
  const words: string[] = []
  for (const token of raw.trim().split(/\s+/)) {
    if (!token) continue
    const match = NUMBER_TOKEN.exec(token)
    if (match) numbers.push(Number.parseInt(match[1], 10))
    else words.push(token.toLowerCase())
  }
  return { numbers, words }
}

export function isEmptySearch(search: ParsedThreatSearch): boolean {
  return search.numbers.length === 0 && search.words.length === 0
}

/**
 * Whether a threat matches: every number must be the threat's number and
 * every word must appear in the name (or the targets' names, so "PLC" finds
 * what sits on the PLC).
 */
export function threatMatchesSearch(
  threat: { number: number; threatName?: string | null; targetNames?: string[] },
  search: ParsedThreatSearch
): boolean {
  if (isEmptySearch(search)) return true
  if (search.numbers.some((number) => number !== threat.number)) return false
  const haystack = [threat.threatName ?? '', ...(threat.targetNames ?? [])].join(' ').toLowerCase()
  return search.words.every((word) => haystack.includes(word))
}
