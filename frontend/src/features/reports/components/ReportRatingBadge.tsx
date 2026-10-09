/**
 * A report rating (`ReportRating`, the flat shape of report_service._rating)
 * shown with the shared RatingBadge: level, score on the native scale and,
 * when asked, the methodology.
 */

import { RatingBadge } from '@/features/threat-models/components/rating/RatingBadge'
import type { ReportRating } from '@/features/reports/types/report'

interface ReportRatingBadgeProps {
  rating: ReportRating | null | undefined
  showMethodology?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export function ReportRatingBadge({ rating, showMethodology = false, size = 'sm', className }: ReportRatingBadgeProps) {
  return (
    <RatingBadge
      level={rating?.level ?? null}
      score={rating?.score ?? null}
      methodology={rating?.methodology ?? null}
      showMethodology={showMethodology}
      size={size}
      className={className}
    />
  )
}
