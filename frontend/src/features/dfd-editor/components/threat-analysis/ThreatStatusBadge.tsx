/** The state pill of a threat ("exposed", "addressable", "mitigated"): colour and word together. */

import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { ThreatStatus } from '../../types/threat-analysis'
import { THREAT_STATUS_CONFIG } from '../../types/threat-analysis'

export function ThreatStatusBadge({ status }: { status: ThreatStatus }) {
  const config = THREAT_STATUS_CONFIG[status]
  return (
    <Badge variant="outline" className={cn('shrink-0 text-xs', config.bgColor)} data-threat-status={status}>
      {config.label}
    </Badge>
  )
}
