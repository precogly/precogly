/**
 * A rating shown as a badge: the level, the score on its native scale and,
 * when asked, the methodology (#31 comment, section 2.8). Used for threats
 * (one rating) and risks (inherent, residual, target).
 */

import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { Rating, RatingLevel } from '@/types/risk'
import { RATING_LEVEL_CLASSES, formatRatingScore, methodologyLabel, ratingLevelLabel } from './rating-utils'

export interface RatingBadgeProps {
  /** A full rating, or null for "unrated". `level` and `score` below override it. */
  rating?: Rating | null
  level?: RatingLevel | null
  score?: number | null
  methodology?: string | null
  /** The method's native scale, shown after the score ("/ 25"). */
  scoreScale?: string | null
  /** Show the methodology after the level. */
  showMethodology?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function RatingBadge({
  rating,
  level,
  score,
  methodology,
  scoreScale,
  showMethodology = false,
  size = 'md',
  className,
}: RatingBadgeProps) {
  const effectiveLevel = level ?? rating?.level ?? null
  const effectiveScore = score !== undefined ? score : (rating?.score ?? null)
  const effectiveMethodology = methodology ?? rating?.methodology ?? null
  const scoreText = formatRatingScore(effectiveScore, scoreScale)
  const levelClasses = effectiveLevel
    ? RATING_LEVEL_CLASSES[effectiveLevel]
    : 'bg-muted text-muted-foreground border-transparent'

  return (
    <Badge
      variant="outline"
      className={cn(
        'inline-flex items-center gap-1 font-medium capitalize',
        size === 'sm' ? 'text-[10px] px-1.5 py-0' : 'text-xs',
        levelClasses,
        className
      )}
      title={effectiveMethodology ? methodologyLabel(effectiveMethodology) : undefined}
      data-level={effectiveLevel ?? 'unrated'}
    >
      <span>{ratingLevelLabel(effectiveLevel)}</span>
      {scoreText && <span className="font-normal normal-case opacity-80">{scoreText}</span>}
      {showMethodology && effectiveMethodology && (
        <span className="font-normal normal-case opacity-70">{methodologyLabel(effectiveMethodology)}</span>
      )}
    </Badge>
  )
}
