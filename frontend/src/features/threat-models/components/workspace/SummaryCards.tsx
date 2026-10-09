import { Box, ShieldAlert, Shield } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface ComponentSummary {
  total: number
  processes: number
  datastores: number
  humanActors: number
  systemActors: number
  trustZones: number
}

interface ThreatSummary {
  total: number
  exposed: number
  addressable: number
  mitigated: number
}

interface CountermeasureSummary {
  total: number
  platform: number
  verified: number
  gap: number
  planned: number
  waived: number
}

interface SummaryCardsProps {
  components: ComponentSummary
  threats: ThreatSummary
  countermeasures: CountermeasureSummary
  /** The counts cover every blueprint (plan 11.5); with more than one a note says so. */
  blueprintCount?: number
  onComponentsClick?: () => void
  onThreatsClick?: () => void
  onCountermeasuresClick?: () => void
}

export function SummaryCards({
  components,
  threats,
  countermeasures,
  blueprintCount,
  onComponentsClick,
  onThreatsClick,
  onCountermeasuresClick,
}: SummaryCardsProps) {
  return (
    <div className="space-y-2">
      {blueprintCount !== undefined && blueprintCount > 1 && (
        <p className="text-xs text-muted-foreground">Counts cover all {blueprintCount} blueprints.</p>
      )}
    <div className="grid grid-cols-3 gap-4">
      {/* In-Scope Components */}
      <Card
        className={cn(
          'cursor-pointer transition-colors hover:border-primary/50',
          onComponentsClick && 'cursor-pointer'
        )}
        onClick={onComponentsClick}
      >
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Box className="h-4 w-4 text-muted-foreground" />
            In-Scope Components
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold">{components.total}</div>
          <div className="flex flex-wrap gap-2 mt-2 text-xs text-muted-foreground">
            {components.processes > 0 && (
              <span>{components.processes} processes</span>
            )}
            {components.datastores > 0 && (
              <span>{components.datastores} datastores</span>
            )}
            {components.humanActors > 0 && (
              <span>{components.humanActors} human actors</span>
            )}
            {components.systemActors > 0 && (
              <span>{components.systemActors} system actors</span>
            )}
            {components.trustZones > 0 && (
              <span>{components.trustZones} zones</span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Threats */}
      <Card
        className={cn(
          'transition-colors hover:border-primary/50',
          onThreatsClick && 'cursor-pointer'
        )}
        onClick={onThreatsClick}
      >
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
            Threats
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold">{threats.total}</div>
          <div className="flex gap-3 mt-2">
            {threats.exposed > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                <span className="text-xs text-muted-foreground">
                  {threats.exposed} exposed
                </span>
              </div>
            )}
            {threats.addressable > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-yellow-500" />
                <span className="text-xs text-muted-foreground">
                  {threats.addressable} addressable
                </span>
              </div>
            )}
            {threats.mitigated > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-xs text-muted-foreground">
                  {threats.mitigated} mitigated
                </span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Countermeasures */}
      <Card
        className={cn(
          'transition-colors hover:border-primary/50',
          onCountermeasuresClick && 'cursor-pointer'
        )}
        onClick={onCountermeasuresClick}
      >
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            Countermeasures
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold">{countermeasures.total}</div>
          <div className="flex gap-3 mt-2">
            {countermeasures.platform > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-xs text-muted-foreground">
                  {countermeasures.platform} platform
                </span>
              </div>
            )}
            {countermeasures.verified > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-xs text-muted-foreground">
                  {countermeasures.verified} verified
                </span>
              </div>
            )}
            {countermeasures.gap > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                <span className="text-xs text-muted-foreground">
                  {countermeasures.gap} gaps
                </span>
              </div>
            )}
            {countermeasures.planned > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-yellow-500" />
                <span className="text-xs text-muted-foreground">
                  {countermeasures.planned} planned
                </span>
              </div>
            )}
            {countermeasures.waived > 0 && (
              <div className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-blue-500" />
                <span className="text-xs text-muted-foreground">
                  {countermeasures.waived} waived
                </span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
    </div>
  )
}
