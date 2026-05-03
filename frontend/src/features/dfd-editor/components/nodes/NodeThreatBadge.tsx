import { memo } from 'react'
import { cn } from '@/lib/utils'
import { useThreatSummary } from '../../contexts/ThreatSummaryContext'

interface NodeThreatBadgeProps {
  nodeId: string
  className?: string
}

/** Canvas pill: threat workload + native tooltip with worst inherent/residual severities. */
export const NodeThreatBadge = memo(function NodeThreatBadge({ nodeId, className }: NodeThreatBadgeProps) {
  const s = useThreatSummary(nodeId)
  if (!s || s.total <= 0) return null

  const tone =
    s.exposed > 0 ? 'exposed' : s.addressable > 0 ? 'addressable' : 'mitigated'
  const label =
    s.exposed > 0
      ? `${s.exposed} exposed`
      : s.addressable > 0
        ? `${s.addressable} in progress`
        : `${s.total} mitigated`

  const tipParts = [`${s.total} active threat(s)`, label]
  if (s.worstInherent) tipParts.push(`Worst inherent: ${s.worstInherent}`)
  if (s.worstResidual) tipParts.push(`Worst residual: ${s.worstResidual}`)

  return (
    <div
      title={tipParts.join(' · ')}
      className={cn(
        'text-[10px] px-1.5 py-0.5 rounded font-medium',
        tone === 'exposed' && 'bg-red-100 text-red-700',
        tone === 'addressable' && 'bg-yellow-100 text-yellow-700',
        tone === 'mitigated' && 'bg-green-100 text-green-700',
        className
      )}
    >
      {label}
    </div>
  )
})
