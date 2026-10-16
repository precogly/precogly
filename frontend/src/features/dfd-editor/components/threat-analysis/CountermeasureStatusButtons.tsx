import { Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { CountermeasureStatus } from '../../types/threat-analysis'
import { COUNTERMEASURE_STATUS_CONFIG } from '../../types/threat-analysis'
import { countermeasureStatusAction, countermeasureStatusOptions } from './countermeasure-utils'

export function CountermeasureStatusButtons({
  status,
  isPlatformLevel,
  isSecurityTeam,
  hasOwner,
  onChange,
  onPlannedWithoutOwner,
  onWaivedWithoutReason,
}: {
  status: CountermeasureStatus
  isPlatformLevel: boolean
  isSecurityTeam?: boolean
  hasOwner: boolean
  onChange: (status: CountermeasureStatus) => void
  onPlannedWithoutOwner: () => void
  onWaivedWithoutReason: () => void
}) {
  const statuses = countermeasureStatusOptions({ isSecurityTeam })

  const handleStatusClick = (newStatus: CountermeasureStatus) => {
    const action = countermeasureStatusAction(newStatus, hasOwner)
    if (action === 'assign-owner') onPlannedWithoutOwner()
    else if (action === 'waive') onWaivedWithoutReason()
    else onChange(newStatus)
  }

  return (
    <div className="flex items-center gap-1">
      {/* Non-security users see locked Platform badge for platform countermeasures */}
      {!isSecurityTeam && isPlatformLevel && status === 'platform' && (
        <Badge
          variant="outline"
          className="bg-green-100 text-green-700 border-green-300 cursor-default"
        >
          <Lock className="h-3 w-3 mr-1" />
          Platform
        </Badge>
      )}
      {statuses.map((s) => {
        const config = COUNTERMEASURE_STATUS_CONFIG[s]
        const isActive = status === s
        return (
          <Button
            key={s}
            variant={isActive ? 'default' : 'outline'}
            size="sm"
            className={cn(
              'h-7 px-2 text-xs',
              isActive && s === 'platform' && 'bg-green-600 hover:bg-green-700',
              isActive && s === 'gap' && 'bg-red-500 hover:bg-red-600',
              isActive && s === 'planned' && 'bg-yellow-500 hover:bg-yellow-600 text-black',
              isActive && s === 'verified' && 'bg-green-500 hover:bg-green-600',
              isActive && s === 'waived' && 'bg-blue-500 hover:bg-blue-600'
            )}
            onClick={() => handleStatusClick(s)}
          >
            {config.label}
          </Button>
        )
      })}
    </div>
  )
}