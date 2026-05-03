import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Shield, Plus, Zap, ChevronDown, ChevronUp, AlertTriangle, Link2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'
import { AddThreatDialog } from '../threat-analysis/AddThreatDialog'
import { AddCountermeasureDialog } from '../threat-analysis/AddCountermeasureDialog'
import { useComponentThreats, useGenerateThreats } from '@/features/threat-models/api/threats'
import type { ComponentInstanceCountermeasure, GenerateThreatsResponse } from '@/features/threat-models/api/threats'
import { THREAT_STATUS_CONFIG, COUNTERMEASURE_STATUS_CONFIG } from '../../types/threat-analysis'
import type { ThreatStatus, CountermeasureStatus } from '../../types/threat-analysis'

interface NodeThreatSectionProps {
  componentId: number
  componentName: string
}

function toThreatStatus(s: string): ThreatStatus {
  if (s === 'mitigated') return 'mitigated'
  if (s === 'addressable') return 'addressable'
  return 'exposed'
}

function formatSeverityLabel(value: string | undefined | null): string {
  const v = String(value ?? '').trim().toLowerCase()
  if (!v) return 'Not assessed'
  return v
}

function sortedCountermeasures(list: ComponentInstanceCountermeasure[] | undefined) {
  if (!list?.length) return []
  return [...list].sort(
    (a, b) => (a.displayOrder ?? 0) - (b.displayOrder ?? 0) || a.id - b.id
  )
}

function CountermeasureRow({
  cm,
}: {
  cm: ComponentInstanceCountermeasure
}) {
  const status = cm.status as CountermeasureStatus
  const cfg = COUNTERMEASURE_STATUS_CONFIG[status] ?? COUNTERMEASURE_STATUS_CONFIG.gap
  const name =
    cm.countermeasureNameDisplay?.trim() ||
    cm.countermeasureName?.trim() ||
    'Countermeasure'

  return (
    <div
      className={cn(
        'rounded border px-2 py-1.5 text-[11px] space-y-1',
        cm.isInherited ? 'border-blue-200 bg-blue-50/50' : 'border-border bg-muted/30'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="font-medium leading-snug text-foreground line-clamp-2">{name}</span>
        <div className="flex items-center gap-1 shrink-0">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
          <span className="text-[9px] font-medium capitalize text-foreground">{cfg.label}</span>
        </div>
      </div>
      {cm.assignedOwnerEmail && (
        <p className="text-muted-foreground">
          Owner: <span className="text-foreground">{cm.assignedOwnerEmail}</span>
        </p>
      )}
      {cm.isInherited && (cm.inheritedFromZoneName || cm.inheritedFromComponentName) && (
        <p className="flex items-center gap-1 text-blue-800/90">
          <Link2 className="h-3 w-3 shrink-0" />
          <span>
            Inherited
            {cm.inheritedFromZoneName ? ` from zone “${cm.inheritedFromZoneName}”` : ''}
            {cm.inheritedFromComponentName && !cm.inheritedFromZoneName
              ? ` from “${cm.inheritedFromComponentName}”`
              : ''}
          </span>
        </p>
      )}
    </div>
  )
}

export function NodeThreatSection({ componentId, componentName }: NodeThreatSectionProps) {
  const [expanded, setExpanded] = useState(true)
  const [addThreatOpen, setAddThreatOpen] = useState(false)
  const [addCountermeasureFor, setAddCountermeasureFor] = useState<{
    threatId: number
    threatName: string
    threatLibraryId?: number | null
  } | null>(null)

  const { data: threats = [], isLoading } = useComponentThreats(componentId)
  const generateMutation = useGenerateThreats()

  const activeThreats = useMemo(() => threats.filter((t) => !t.isDismissed), [threats])
  const exposedCount = activeThreats.filter((t) => t.status === 'exposed').length

  return (
    <>
      <Separator />
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label
            className="flex items-center gap-1.5 cursor-pointer"
            onClick={() => setExpanded((v) => !v)}
          >
            <Shield className="h-3.5 w-3.5 text-red-500" />
            Threats
            {activeThreats.length > 0 && (
              <Badge
                variant="outline"
                className={cn(
                  'h-5 px-1.5 text-[10px]',
                  exposedCount > 0 ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
                )}
              >
                {activeThreats.length}
              </Badge>
            )}
          </Label>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              title="Generate threats from library"
              disabled={generateMutation.isPending}
              onClick={() =>
                generateMutation.mutate(componentId, {
                  onSuccess: (result: GenerateThreatsResponse) => {
                    if (result.createdCount > 0) {
                      toast.success(
                        `Generated ${result.createdCount} new threat${result.createdCount !== 1 ? 's' : ''}`
                      )
                    } else {
                      toast.info(`No new threats — ${result.existingCount} already up to date`)
                    }
                  },
                  onError: () => {
                    toast.error('Failed to generate threats')
                  },
                })
              }
            >
              <Zap className="h-3 w-3" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              title="Add threat"
              onClick={() => setAddThreatOpen(true)}
            >
              <Plus className="h-3 w-3" />
            </Button>
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setExpanded((v) => !v)}>
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </Button>
          </div>
        </div>

        {expanded && (
          <div className="space-y-2">
            {isLoading && <p className="text-xs text-muted-foreground py-1">Loading threats...</p>}

            {!isLoading && activeThreats.length === 0 && (
              <div className="rounded-lg border border-dashed border-border px-3 py-4 text-center space-y-1">
                <p className="text-xs text-muted-foreground">No threats yet.</p>
                <p className="text-[11px] text-muted-foreground/70">
                  Click <Zap className="inline h-3 w-3" /> to generate from library or{' '}
                  <button
                    className="underline underline-offset-2 hover:text-foreground"
                    onClick={() => setAddThreatOpen(true)}
                  >
                    add manually
                  </button>
                  .
                </p>
              </div>
            )}

            {activeThreats.map((threat) => {
              const status = toThreatStatus(threat.status)
              const statusConfig = THREAT_STATUS_CONFIG[status]
              const displayName =
                threat.threatNameDisplay || threat.threatName || 'Unnamed threat'
              const cms = sortedCountermeasures(threat.countermeasures)

              const statusColors: Record<string, string> = {
                exposed: 'border-red-200 bg-red-50/60',
                addressable: 'border-yellow-200 bg-yellow-50/60',
                mitigated: 'border-green-200 bg-green-50/60',
              }

              return (
                <div
                  key={threat.id}
                  className={cn(
                    'rounded-lg border px-3 py-2.5 space-y-2',
                    statusColors[status] ?? 'border-border bg-muted/40'
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0 flex-1">
                      {status === 'exposed' && (
                        <AlertTriangle className="h-3.5 w-3.5 text-red-500 flex-shrink-0 mt-px" />
                      )}
                      <span className="font-medium text-sm leading-snug line-clamp-2">{displayName}</span>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px] h-5 px-2 flex-shrink-0 capitalize font-medium',
                        statusConfig.bgColor
                      )}
                    >
                      {statusConfig.label}
                    </Badge>
                  </div>

                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
                    <span className="capitalize">
                      Inherent:{' '}
                      <span className="text-foreground font-medium">
                        {formatSeverityLabel(threat.inherentSeverity)}
                      </span>
                    </span>
                    <span className="capitalize">
                      Residual:{' '}
                      <span
                        className={cn(
                          'font-medium',
                          String(threat.residualSeverity ?? '').trim()
                            ? 'text-foreground'
                            : 'text-muted-foreground italic'
                        )}
                      >
                        {formatSeverityLabel(threat.residualSeverity)}
                      </span>
                    </span>
                  </div>

                  {cms.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                        Countermeasures
                      </p>
                      <div className="space-y-1.5">
                        {cms.map((cm) => (
                          <CountermeasureRow key={cm.id} cm={cm} />
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end pt-0.5">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 text-[11px] px-2 gap-1"
                      onClick={() =>
                        setAddCountermeasureFor({
                          threatId: threat.id,
                          threatName: displayName,
                          threatLibraryId: threat.threatLibrary ?? null,
                        })
                      }
                    >
                      <Plus className="h-3 w-3" />
                      Add countermeasure
                    </Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <AddThreatDialog
        open={addThreatOpen}
        onOpenChange={setAddThreatOpen}
        targetId={componentId}
        targetType="component"
        targetName={componentName}
      />

      {addCountermeasureFor && (
        <AddCountermeasureDialog
          open={!!addCountermeasureFor}
          onOpenChange={(open) => {
            if (!open) setAddCountermeasureFor(null)
          }}
          threatId={addCountermeasureFor.threatId}
          threatType="component"
          threatName={addCountermeasureFor.threatName}
          threatLibraryId={addCountermeasureFor.threatLibraryId}
        />
      )}
    </>
  )
}
