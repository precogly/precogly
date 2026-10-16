/**
 * Rules for the authentication and authorization pickers on flows and
 * boundaries (plan 4.5, I5 and I9).
 *
 * `none` cannot be mixed with other values: picking it clears the rest, and
 * picking anything else drops it. `unspecified` ("authenticated, method not
 * recorded") is a placeholder: picking a real method drops it.
 */

import { NO_AUTHENTICATION, UNSPECIFIED_AUTHENTICATION } from '@/types/domain'

/**
 * The list after the picker reports `next`, given what was selected before.
 * Works for any list that includes `none` (authentication and authorization).
 */
export function normalizeExclusiveSelection(previous: readonly string[], next: readonly string[]): string[] {
  const added = next.filter((value) => !previous.includes(value))
  if (added.includes(NO_AUTHENTICATION)) return [NO_AUTHENTICATION]
  let result = next.filter((value) => value !== '')
  if (added.length > 0) {
    result = result.filter((value) => value !== NO_AUTHENTICATION)
  }
  return Array.from(new Set(result))
}

/** The authentication list after a pick: the `none` rule plus the placeholder rule. */
export function normalizeAuthenticationSelection(
  previous: readonly string[],
  next: readonly string[]
): string[] {
  const result = normalizeExclusiveSelection(previous, next)
  const added = next.filter((value) => !previous.includes(value))
  const addedRealMethod = added.some(
    (value) => value !== UNSPECIFIED_AUTHENTICATION && value !== NO_AUTHENTICATION
  )
  if (addedRealMethod) {
    return result.filter((value) => value !== UNSPECIFIED_AUTHENTICATION)
  }
  return result
}
