/**
 * The three ratings of a risk (#31 comment 2.8, plan 11.4): inherent is
 * edited with the shared RatingForm; residual is computed from the linked
 * countermeasures and can be recalculated; target is read-only because the
 * risk serializer takes no target inputs (only `rating_inputs` for inherent).
 * A level-only inherent rating has nothing to reduce from, so its residual is
 * never recalculated (the backend keeps whatever it holds) and the refresh
 * button is disabled. The info popover beside "Ratings" states the rules.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Info, Loader2, Pencil, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useRecalculateRisk, useUpdateRisk } from '@/features/threat-models/api/risks'
import {
  RatingBadge,
  RatingForm,
  ratingInputsComplete,
  ratingInputsFromRating,
} from '@/features/threat-models/components/rating'
import type { Rating, RatingInputs, Risk, ScoringMethod } from '@/types/risk'
import { apiErrorMessage } from './risk-utils'

export interface RiskRatingSectionProps {
  threatModelId: string
  risk: Risk
  /** The model's method, from `/scoring-methods/`; undefined while loading. */
  scoringMethod: ScoringMethod | undefined
  scoringMethods: ScoringMethod[] | undefined
}

function scaleFor(rating: Rating | null, scoringMethods: ScoringMethod[] | undefined): string | null {
  if (!rating) return null
  return scoringMethods?.find((method) => method.key === rating.methodology)?.scoreScale ?? null
}

/** Whether the inherent rating has a likelihood the backend can scale by control effectiveness. */
function residualIsRecalculated(inherent: Rating | null): boolean {
  return inherent !== null && inherent.methodology !== 'manual' && inherent.likelihood !== null
}

const RESIDUAL_RULES =
  'Residual is the inherent rating after the linked threats\' countermeasures. Each countermeasure counts its ' +
  'effectiveness, or when not assessed a default by status: Verified and Platform 100%, Implemented 70%, ' +
  'In Progress 50%, Planned 30%, Gap, Waived and Decommissioned 0%. The average lowers the likelihood; impact ' +
  'does not change. Level-only ratings are not recalculated.'

const LEVEL_ONLY_RECALCULATE_TITLE = 'Level-only ratings are not recalculated. The residual keeps the level it was given.'

export function RiskRatingSection({ threatModelId, risk, scoringMethod, scoringMethods }: RiskRatingSectionProps) {
  const updateRisk = useUpdateRisk(threatModelId)
  const recalculateRisk = useRecalculateRisk(threatModelId)
  const [editing, setEditing] = useState(false)
  const [ratingInputs, setRatingInputs] = useState<RatingInputs | null>(null)

  // A method without an engine (fair, mozilla-rra) rates by level.
  const ratingMethod = scoringMethod?.available ? risk.scoringMethod : 'manual'

  const startEditing = () => {
    setRatingInputs(ratingInputsFromRating(risk.inherent, ratingMethod))
    setEditing(true)
  }

  const saveRating = () => {
    if (!ratingInputs) return
    updateRisk.mutate(
      { riskId: risk.id, data: { ratingInputs } },
      {
        onSuccess: () => setEditing(false),
        onError: (error) => toast.error(apiErrorMessage(error, 'Failed to save the rating.')),
      }
    )
  }

  const recalculate = () => {
    recalculateRisk.mutate(risk.id, {
      onError: (error) => toast.error(apiErrorMessage(error, 'Failed to recalculate the residual rating.')),
    })
  }

  const canRecalculate = residualIsRecalculated(risk.inherent)

  return (
    <div className="space-y-2" data-testid="risk-ratings">
      <div className="flex items-center gap-1">
        <p className="text-xs text-muted-foreground">Ratings</p>
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="ghost" size="sm" className="h-5 w-5 p-0" aria-label="How the residual rating is calculated">
              <Info className="h-3 w-3 text-muted-foreground" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-80 text-xs leading-relaxed" data-testid="residual-rules">
            {RESIDUAL_RULES}
          </PopoverContent>
        </Popover>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <span className="flex items-center gap-1.5">
          <span className="text-muted-foreground">Inherent:</span>
          <RatingBadge rating={risk.inherent} scoreScale={scaleFor(risk.inherent, scoringMethods)} />
        </span>
        <span className="flex items-center gap-1.5">
          <span className="text-muted-foreground">Residual:</span>
          <RatingBadge rating={risk.residual} scoreScale={scaleFor(risk.residual, scoringMethods)} />
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            title={canRecalculate ? 'Recalculate residual rating' : LEVEL_ONLY_RECALCULATE_TITLE}
            aria-label="Recalculate residual rating"
            disabled={recalculateRisk.isPending || !canRecalculate}
            onClick={recalculate}
          >
            <RefreshCw className={`h-3 w-3 text-muted-foreground ${recalculateRisk.isPending ? 'animate-spin' : ''}`} />
          </Button>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="text-muted-foreground">Target:</span>
          <RatingBadge rating={risk.target} scoreScale={scaleFor(risk.target, scoringMethods)} />
        </span>
        {!editing && (
          <Button variant="outline" size="sm" className="h-7 text-xs ml-auto" onClick={startEditing}>
            <Pencil className="h-3 w-3 mr-1" />
            Edit rating
          </Button>
        )}
      </div>
      {editing && ratingInputs && (
        <div className="rounded-md border p-3 space-y-3">
          <RatingForm
            method={ratingMethod}
            scoringMethod={scoringMethod}
            value={ratingInputs}
            onChange={setRatingInputs}
            disabled={updateRisk.isPending}
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setEditing(false)} disabled={updateRisk.isPending}>
              Cancel
            </Button>
            <Button size="sm" onClick={saveRating} disabled={updateRisk.isPending || !ratingInputsComplete(ratingInputs)}>
              {updateRisk.isPending && <Loader2 className="h-3 w-3 animate-spin mr-1" />}
              Save rating
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
