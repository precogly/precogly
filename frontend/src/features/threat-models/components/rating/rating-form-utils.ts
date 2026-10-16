/**
 * The RatingForm's value helpers: empty inputs per mode, pre-filling from an
 * existing rating (#31, 2.10) and completeness. Kept out of the component
 * file so fast refresh works.
 */

import {
  OWASP_GROUPS,
  isLevelOnlyInputs,
  isMatrixInputs,
  isOwaspInputs,
  type ImpactExtraInputs,
  type OwaspRiskRatingInputs,
  type Rating,
  type RatingInputs,
  type ScoringMethodKey,
  MATRIX_IMPACT_FROM_LEVEL,
  MATRIX_LIKELIHOOD_FROM_LEVEL,
  ratingImpactExtra,
} from '@/types/risk'

/** The methods the form has a mode for; anything else falls back to `manual`. */
export type RatingFormMethod = ScoringMethodKey | 'manual'

export type RatingFormMode = 'qualitative-matrix' | 'owasp-risk-rating' | 'manual'

/** The mode the form shows for a method: a method with no engine rates by level. */
export function ratingFormMode(method: RatingFormMethod | string | undefined): RatingFormMode {
  if (method === 'qualitative-matrix' || method === 'owasp-risk-rating') return method
  return 'manual'
}

function emptyOwaspGroup(fields: string[]): Record<string, number> {
  return Object.fromEntries(fields.map((field) => [field, 0]))
}

/** Empty inputs for a mode, so the form always has a complete value to edit. */
export function emptyRatingInputs(method: RatingFormMethod | string | undefined): RatingInputs {
  switch (ratingFormMode(method)) {
    case 'qualitative-matrix':
      return { likelihood: 'possible', impact: 'moderate', rationale: '' }
    case 'owasp-risk-rating':
      return {
        threatAgent: emptyOwaspGroup(OWASP_GROUPS[0].fields) as OwaspRiskRatingInputs['threatAgent'],
        vulnerability: emptyOwaspGroup(OWASP_GROUPS[1].fields) as OwaspRiskRatingInputs['vulnerability'],
        technicalImpact: emptyOwaspGroup(OWASP_GROUPS[2].fields) as OwaspRiskRatingInputs['technicalImpact'],
        businessImpact: emptyOwaspGroup(OWASP_GROUPS[3].fields) as OwaspRiskRatingInputs['businessImpact'],
        rationale: '',
      }
    default:
      return { level: 'medium', rationale: '' }
  }
}

/**
 * The inputs that reproduce an existing rating, for pre-filling (#31, 2.10).
 * The matrix is rebuilt from the stored levels; OWASP from the stored factor
 * scores (in group order); anything else becomes a level-only rating.
 */
export function ratingInputsFromRating(
  rating: Rating | null | undefined,
  method: RatingFormMethod | string | undefined
): RatingInputs {
  const empty = emptyRatingInputs(method)
  if (!rating) return empty
  const extra = ratingImpactExtra(rating)
  const impactExtra: ImpactExtraInputs = {
    ...(extra.categories.length > 0 && { impactCategories: extra.categories }),
    ...(Object.keys(extra.quantification).length > 0 && { impactQuantification: extra.quantification }),
  }
  const mode = ratingFormMode(method)

  if (mode === 'qualitative-matrix' && rating.methodology === 'qualitative-matrix') {
    const likelihood = MATRIX_LIKELIHOOD_FROM_LEVEL[rating.likelihood?.level ?? '']
    const impact = MATRIX_IMPACT_FROM_LEVEL[rating.impact?.level ?? '']
    if (likelihood && impact) {
      return { likelihood, impact, rationale: rating.rationale, ...impactExtra }
    }
  }

  if (mode === 'owasp-risk-rating' && rating.methodology === 'owasp-risk-rating') {
    const likelihoodScores = (rating.likelihood?.factors ?? []).map((factor) => factor.score)
    const impactScores = (rating.impact?.factors ?? []).map((factor) => factor.score)
    if (likelihoodScores.length === 8 && impactScores.length === 8) {
      const scores = [...likelihoodScores, ...impactScores]
      let index = 0
      const groups = OWASP_GROUPS.map((group) => {
        const values: Record<string, number> = {}
        for (const field of group.fields) values[field] = scores[index++]
        return values
      })
      return {
        threatAgent: groups[0] as OwaspRiskRatingInputs['threatAgent'],
        vulnerability: groups[1] as OwaspRiskRatingInputs['vulnerability'],
        technicalImpact: groups[2] as OwaspRiskRatingInputs['technicalImpact'],
        businessImpact: groups[3] as OwaspRiskRatingInputs['businessImpact'],
        rationale: rating.rationale,
        ...impactExtra,
      }
    }
  }

  if (mode === 'manual') {
    return { level: rating.level, rationale: rating.rationale, ...impactExtra }
  }
  return { ...empty, ...impactExtra }
}

/** Whether the inputs are complete enough to submit. */
export function ratingInputsComplete(inputs: RatingInputs): boolean {
  if (isOwaspInputs(inputs)) {
    return OWASP_GROUPS.every((group) => {
      const values = inputs[group.key] as Record<string, number> | undefined
      return group.fields.every((field) => Number.isInteger(values?.[field]))
    })
  }
  if (isMatrixInputs(inputs)) return Boolean(inputs.likelihood && inputs.impact)
  if (isLevelOnlyInputs(inputs)) return Boolean(inputs.level)
  return false
}
