/**
 * The one "is it authenticated" rule for flows and boundaries (plan I5).
 *
 * The spec's authentication and authorization lists include the value
 * `none`. A requirement is recorded when the list is not empty and does not
 * contain `none`; an empty list means "not recorded". The backend has the
 * same helper (`apps.systems.crossing.requires`). Everything that used to
 * read the old boolean `authenticated` reads this instead: the editor, the
 * reports, the Word export and the pentest scope transformers.
 */

export const AUTHENTICATION_NONE = 'none'

/** True when the list records a requirement: not empty and not `none`. */
export function isAuthenticated(values: readonly string[] | null | undefined): boolean {
  if (!values || values.length === 0) return false
  return !values.includes(AUTHENTICATION_NONE)
}

/** The same rule for a boundary's or flow's authorization list. */
export const requiresAuthorization = isAuthenticated
