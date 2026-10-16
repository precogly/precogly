/** Wording for model relationships, from this model's side (plan J15). */

import { RELATION_TYPES, type RelationType } from '@/types/domain'
import type { RelatedModel } from '@/features/threat-models/types/core'

export function relationTypeLabel(relationType: RelationType): string {
  return RELATION_TYPES.find((option) => option.value === relationType)?.label ?? relationType
}

/** The sentence for one relationship, read from this model's side. */
export function relationSentence(relationship: RelatedModel): string {
  const label = relationTypeLabel(relationship.relationType)
  if (relationship.direction === 'outgoing') return `This model ${label} ${relationship.model.name}`
  return `${relationship.model.name} ${label} this model`
}
