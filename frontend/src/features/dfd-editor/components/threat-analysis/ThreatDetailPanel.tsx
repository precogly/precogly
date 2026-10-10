/**
 * The detail of a selected scenario (plan 11.11 "Threat" row): the rating
 * form (matrix or level only), the actor (persona or text), the impact, the
 * business objectives once the model has one (J4), the threat sources, and
 * intent and access level read-only when an import set them (J11, J12). Edits
 * apply to the one scenario, so they show under every target at once.
 *
 * The caller keys the panel by threat id, so the form starts from the
 * scenario's values on each selection. The objectives come from the threat
 * row, so the form mounts once that row is here.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import { RatingBadge, RatingForm, ratingInputsFromRating } from '@/features/threat-models/components/rating'
import {
  useThreat,
  useUpdateThreat,
  type InstanceThreat,
  type ThreatPersona,
  type UpdateThreatInput,
} from '@/features/threat-models/api/threats'
import { ApiError } from '@/lib/api'
import type { RatingInputs } from '@/types/risk'
import { THREAT_ACCESS_LEVELS, THREAT_INTENTS } from '@/types/domain'
import type { AnalysisThreat } from '../../types/threat-analysis'
import { ActorPicker } from './ActorPicker'
import { type ActorValue } from './actor-utils'
import { BusinessObjectivesPicker } from './BusinessObjectivesPicker'
import { ThreatSourcesPicker } from './ThreatSourcesPicker'
import { threatSourceIdsFromThreat } from './threat-source-selection'
import { useHasBusinessObjectives } from './useHasBusinessObjectives'

type ThreatRatingMethod = 'qualitative-matrix' | 'manual'

function initialRatingMethod(threat: AnalysisThreat): ThreatRatingMethod {
  return threat.rating?.methodology === 'qualitative-matrix' ? 'qualitative-matrix' : 'manual'
}

function actorFromThreat(threat: AnalysisThreat): ActorValue {
  if (threat.actorPersonaId != null) return { actorPersona: threat.actorPersonaId, threatActorText: '' }
  return { actorPersona: null, threatActorText: threat.threatActorText ?? '' }
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.data && typeof error.data === 'object') {
    const firstValue = Object.values(error.data as Record<string, unknown>)[0]
    if (typeof firstValue === 'string') return firstValue
    if (Array.isArray(firstValue) && typeof firstValue[0] === 'string') return firstValue[0]
  }
  return fallback
}

interface ThreatDetailPanelProps {
  threatModelId: string
  threat: AnalysisThreat
  personas: ThreatPersona[]
}

export function ThreatDetailPanel({ threatModelId, threat, personas }: ThreatDetailPanelProps) {
  const { data: threatDetail, isLoading } = useThreat(threat.backendThreatId)
  if (isLoading || !threatDetail) {
    return (
      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" /> Loading
      </div>
    )
  }
  return <ThreatDetailForm threatModelId={threatModelId} threat={threat} threatDetail={threatDetail} personas={personas} />
}

function ThreatDetailForm({
  threatModelId,
  threat,
  threatDetail,
  personas,
}: ThreatDetailPanelProps & { threatDetail: InstanceThreat }) {
  const updateThreat = useUpdateThreat()
  const hasObjectives = useHasBusinessObjectives(threatModelId)

  const [ratingMethod, setRatingMethod] = useState<ThreatRatingMethod>(() => initialRatingMethod(threat))
  const [ratingInputs, setRatingInputs] = useState<RatingInputs>(() =>
    ratingInputsFromRating(threat.rating, initialRatingMethod(threat))
  )
  const [actor, setActor] = useState<ActorValue>(() => actorFromThreat(threat))
  const [impactDescription, setImpactDescription] = useState(threat.impactDescription ?? '')
  const [objectiveIds, setObjectiveIds] = useState<number[]>(
    () => threatDetail.businessObjectiveIds ?? threatDetail.businessObjectives.map((objective) => objective.id)
  )

  const [threatSourceIds, setThreatSourceIds] = useState<number[]>(() =>
    threatSourceIdsFromThreat(threatDetail.threatSources ?? threat.threatSources)
  )

  const switchRatingMethod = (method: ThreatRatingMethod) => {
    setRatingMethod(method)
    setRatingInputs(ratingInputsFromRating(threat.rating, method))
  }

  const handleSave = () => {
    const data: UpdateThreatInput = {
      ratingInputs,
      impactDescription,
      actorPersona: actor.actorPersona,
      // One actor: the text is cleared when a persona is chosen (K3).
      threatActorText: actor.actorPersona !== null ? '' : actor.threatActorText,
      threatSourceIds,
    }
    if (hasObjectives) data.businessObjectiveIds = objectiveIds
    updateThreat.mutate(
      { threatId: threat.backendThreatId, data },
      {
        onSuccess: () => toast.success('Threat saved'),
        onError: (error) => toast.error(errorMessage(error, 'Could not save the threat')),
      }
    )
  }

  const intentLabel = THREAT_INTENTS.find((entry) => entry.value === threat.intent)?.label
  const accessLevelLabel = THREAT_ACCESS_LEVELS.find((entry) => entry.value === threat.accessLevel)?.label
  const showReadOnly = Boolean(intentLabel || accessLevelLabel)

  return (
    <div className="space-y-3" onClick={(event) => event.stopPropagation()}>
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Rating</div>
          <div className="flex items-center gap-2">
            <RatingBadge
              rating={threat.rating}
              size="sm"
              scoreScale={threat.rating?.methodology === 'qualitative-matrix' ? '25' : null}
            />
            <div className="flex rounded-md border p-0.5 text-[11px]">
              {(
                [
                  ['qualitative-matrix', 'Likelihood x impact'],
                  ['manual', 'Level only'],
                ] as const
              ).map(([method, label]) => (
                <button
                  key={method}
                  type="button"
                  className={cn(
                    'rounded px-1.5 py-0.5',
                    ratingMethod === method ? 'bg-slate-200 font-medium' : 'text-muted-foreground hover:text-foreground'
                  )}
                  onClick={() => switchRatingMethod(method)}
                  aria-pressed={ratingMethod === method}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>
        <RatingForm method={ratingMethod} value={ratingInputs} onChange={setRatingInputs} />
      </div>

      <div>
        <div className="mb-1 text-xs font-medium text-muted-foreground">Actor</div>
        <ActorPicker threatModelId={threatModelId} personas={personas} value={actor} onChange={setActor} />
      </div>

      <div>
        <div className="mb-1 text-xs font-medium text-muted-foreground">Threat sources</div>
        <ThreatSourcesPicker value={threatSourceIds} onChange={setThreatSourceIds} />
      </div>

      <div>
        <div className="mb-1 text-xs font-medium text-muted-foreground">Attacker impact</div>
        <Textarea
          value={impactDescription}
          onChange={(event) => setImpactDescription(event.target.value)}
          placeholder="What does the attacker achieve?"
          className="min-h-[56px] resize-y text-xs"
          rows={2}
        />
      </div>

      {hasObjectives && (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Business objectives</div>
          <BusinessObjectivesPicker threatModelId={threatModelId} value={objectiveIds} onChange={setObjectiveIds} />
        </div>
      )}

      {showReadOnly && (
        <div className="rounded border bg-background px-2 py-1.5 text-[11px] text-muted-foreground">
          <span className="mr-1 font-medium">From import:</span>
          {[intentLabel && `Intent: ${intentLabel}`, accessLevelLabel && `Access level: ${accessLevelLabel}`]
            .filter(Boolean)
            .join(' · ')}
        </div>
      )}

      <Button size="sm" className="h-7 w-full text-xs" onClick={handleSave} disabled={updateThreat.isPending}>
        {updateThreat.isPending ? (
          <>
            <Loader2 className="mr-1 h-3 w-3 animate-spin" /> Saving
          </>
        ) : (
          'Save'
        )}
      </Button>
    </div>
  )
}
