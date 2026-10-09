/**
 * The system context summary on the model page: assumptions (with the
 * unverified count), out-of-scope items and data assets across every
 * blueprint, with a button that opens the system context dialog.
 */

import { AlertTriangle, ClipboardList, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAssumptions, useThreatModel } from '@/features/threat-models/api/threat-models'
import { useDataAssets } from '@/features/threat-models/api/data-assets'
import { useOutOfScopeItems } from '@/features/threat-models/api/out-of-scope-items'

interface SystemContextSummaryProps {
  threatModelId: string
  onOpen: () => void
}

function count(total: number, singular: string, pluralForm = `${singular}s`): string {
  return `${total} ${total === 1 ? singular : pluralForm}`
}

export function SystemContextSummary({ threatModelId, onOpen }: SystemContextSummaryProps) {
  const { data: threatModel } = useThreatModel(threatModelId)
  const { data: assumptions = [] } = useAssumptions(threatModelId)
  const { data: outOfScopeItems = [] } = useOutOfScopeItems(threatModelId)
  const { data: dataAssets = [] } = useDataAssets(threatModelId)

  const unverifiedCount = assumptions.filter((assumption) => assumption.validity !== 'verified').length
  const criticality = threatModel?.criticality

  return (
    <Card data-testid="system-context-summary">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-muted-foreground" />
              System context
            </CardTitle>
            {criticality && (
              <Badge
                variant="outline"
                className={
                  criticality === 'critical'
                    ? 'border-red-300 bg-red-50 text-red-700'
                    : criticality === 'high'
                      ? 'border-orange-300 bg-orange-50 text-orange-700'
                      : criticality === 'medium'
                        ? 'border-yellow-300 bg-yellow-50 text-yellow-700'
                        : 'border-green-300 bg-green-50 text-green-700'
                }
              >
                <AlertTriangle className="h-3 w-3 mr-1" />
                {criticality.charAt(0).toUpperCase() + criticality.slice(1)} criticality
              </Badge>
            )}
          </div>
          <Button variant="outline" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={onOpen}>
            <ExternalLink className="h-3 w-3" />
            Open system context
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          {count(assumptions.length, 'assumption')}
          {unverifiedCount > 0 && (
            <>
              , <span className="text-amber-700">{unverifiedCount} not verified</span>
            </>
          )}
          . {count(outOfScopeItems.length, 'out-of-scope item')}. {count(dataAssets.length, 'data asset')}.
        </p>
      </CardContent>
    </Card>
  )
}
