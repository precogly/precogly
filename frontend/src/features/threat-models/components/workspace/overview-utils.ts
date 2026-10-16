/**
 * Pure helpers for the Overview: the muted state under each of the four
 * buttons (System Details, Business objectives, System context, Use cases).
 */

export const NOT_SET_LABEL = 'not set'

export function countLabel(total: number, singular: string, pluralForm = `${singular}s`): string {
  return `${total} ${total === 1 ? singular : pluralForm}`
}

/** "described" once the model has a description or a primary system; otherwise "not set". */
export function systemDetailsSummary(description: string | null | undefined, primarySystemId: number | null | undefined): string {
  return description?.trim() || primarySystemId != null ? 'described' : NOT_SET_LABEL
}

/** "3 objectives", or "not set" with none. */
export function listSummary(total: number, singular: string): string {
  return total === 0 ? NOT_SET_LABEL : countLabel(total, singular)
}

/**
 * The system context in a few words: assumptions with the unverified count,
 * out-of-scope items and data assets; "not set" when all are empty.
 */
export function systemContextSummary(counts: {
  assumptions: number
  unverifiedAssumptions: number
  outOfScopeItems: number
  dataAssets: number
}): string {
  const parts: string[] = []
  if (counts.assumptions > 0) {
    parts.push(
      counts.unverifiedAssumptions > 0
        ? `${countLabel(counts.assumptions, 'assumption')} (${counts.unverifiedAssumptions} not verified)`
        : countLabel(counts.assumptions, 'assumption')
    )
  }
  if (counts.outOfScopeItems > 0) parts.push(`${counts.outOfScopeItems} out of scope`)
  if (counts.dataAssets > 0) parts.push(countLabel(counts.dataAssets, 'data asset'))
  return parts.length === 0 ? NOT_SET_LABEL : parts.join(', ')
}

/**
 * The System button's line, from System Details and System context together:
 * the criticality, whether the system is described, and the context counts.
 * "not set" when there is nothing at all.
 */
export function systemSummary(input: {
  criticality: string | null | undefined
  description: string | null | undefined
  primarySystemId: number | null | undefined
  contextSummary: string
}): string {
  const parts: string[] = []
  if (input.criticality) {
    parts.push(`${input.criticality.charAt(0).toUpperCase()}${input.criticality.slice(1)} criticality`)
  }
  if (systemDetailsSummary(input.description, input.primarySystemId) !== NOT_SET_LABEL) parts.push('described')
  if (input.contextSummary !== NOT_SET_LABEL) parts.push(input.contextSummary)
  return parts.length === 0 ? NOT_SET_LABEL : parts.join(', ')
}
