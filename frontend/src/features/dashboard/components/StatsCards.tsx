import { FileText, BarChart3 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { DashboardStats } from '@/types'
import { RATING_LEVELS, type RatingLevel } from '@/types/risk'
import { RATING_LEVEL_COLORS, ratingLevelLabel } from '@/features/threat-models/components/rating/rating-utils'

interface StatsCardsProps {
  stats: DashboardStats
  isLoading?: boolean
}

const statItems = [
  {
    key: 'total' as const,
    title: 'Total Models',
    icon: FileText,
    className: 'text-blue-600',
  },
]

/**
 * Worst level first, `info` last. Counts come from the backend's grouping of
 * risks by `inherent__level` (core/views.py DashboardStatsView), which includes
 * `info`.
 */
const DASHBOARD_RISK_LEVELS: RatingLevel[] = [...RATING_LEVELS].reverse().map((level) => level.value)

function riskLevelCount(stats: DashboardStats, level: RatingLevel): number {
  return stats.risks?.[level] ?? 0
}

export function StatsCards({ stats, isLoading }: StatsCardsProps) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {statItems.map((item) => (
        <Card key={item.key}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{item.title}</CardTitle>
            <item.icon className={`h-4 w-4 ${item.className}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? <span className="animate-pulse bg-muted rounded w-8 h-8 inline-block" /> : stats[item.key]}
            </div>
          </CardContent>
        </Card>
      ))}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Risks</CardTitle>
          <BarChart3 className="h-4 w-4 text-purple-600" />
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <span className="animate-pulse bg-muted rounded w-8 h-8 inline-block" />
          ) : stats.risks ? (
            <>
              <div className="text-2xl font-bold">{stats.risks.total}</div>
              {stats.risks.total > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {DASHBOARD_RISK_LEVELS.filter((level) => riskLevelCount(stats, level) > 0).map((level) => (
                    <div key={level} className="flex items-center gap-1" title={ratingLevelLabel(level)}>
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: RATING_LEVEL_COLORS[level] }} />
                      <span className="text-xs text-muted-foreground">
                        {riskLevelCount(stats, level)} {ratingLevelLabel(level).toLowerCase()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="text-2xl font-bold">0</div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
