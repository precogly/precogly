import { useBusinessObjectives } from '@/features/threat-models/api/threat-models'

/** Whether the objectives picker would show anything (plan J4: it appears once the model has an objective). */
export function useHasBusinessObjectives(threatModelId: string | null | undefined): boolean {
  const { data: objectives = [] } = useBusinessObjectives(threatModelId)
  return objectives.length > 0
}
