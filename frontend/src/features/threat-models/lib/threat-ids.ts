/**
 * The UI ids of threats and countermeasures (plan section 11.1).
 *
 * A threat is one scenario whatever it targets, so there is one id form,
 * `threat-{id}`. The old `backend-{id}` and `backend-flow-{id}` forms are
 * gone with the two threat tables. Countermeasures keep `cm-{id}`.
 */

const THREAT_PREFIX = 'threat-'
const COUNTERMEASURE_PREFIX = 'cm-'

/** The UI id of a backend threat: `threat-7` for id 7. */
export function threatUiId(threatId: number): string {
  return `${THREAT_PREFIX}${threatId}`
}

/** The backend id behind a threat UI id, or null when the id is not one. */
export function threatIdFromUiId(uiId: string | null | undefined): number | null {
  if (!uiId || !uiId.startsWith(THREAT_PREFIX)) return null
  const parsed = Number.parseInt(uiId.slice(THREAT_PREFIX.length), 10)
  return Number.isNaN(parsed) ? null : parsed
}

export function isThreatUiId(uiId: string | null | undefined): boolean {
  return threatIdFromUiId(uiId) !== null
}

/** The UI id of a backend countermeasure: `cm-3` for id 3. */
export function countermeasureUiId(countermeasureId: number): string {
  return `${COUNTERMEASURE_PREFIX}${countermeasureId}`
}

/** The backend id behind a countermeasure UI id, or null when it is a local one. */
export function countermeasureIdFromUiId(uiId: string | null | undefined): number | null {
  if (!uiId || !uiId.startsWith(COUNTERMEASURE_PREFIX)) return null
  const parsed = Number.parseInt(uiId.slice(COUNTERMEASURE_PREFIX.length), 10)
  return Number.isNaN(parsed) ? null : parsed
}

/**
 * Parse a countermeasure UI id into its type and backend id. `cm-{id}` is a
 * backend row; anything else (for example `ctcm-...`) is local to the editor.
 */
export function parseCountermeasureId(uiId: string): { type: 'backend' | 'local'; id: number | null } {
  if (uiId.startsWith(COUNTERMEASURE_PREFIX)) {
    return { type: 'backend', id: countermeasureIdFromUiId(uiId) }
  }
  return { type: 'local', id: null }
}
