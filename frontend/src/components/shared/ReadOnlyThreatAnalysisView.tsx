/**
 * Read-only threat analysis for the magic-link page. It renders the shared
 * form of the analysis payload (`ThreatAnalysisData`, restricted to the
 * backend's allow-list, M6): number, targets, rating, status and the
 * controls by number. Nothing is derived from the canvas; the diagrams are
 * only a fallback for target names.
 */

import { useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { AlertTriangle, Shield, CheckCircle2, XCircle, Clock, ChevronDown, ChevronRight, Info } from 'lucide-react'
import { isActiveThreat, type TriageStatus } from '@/types/triage'
import { TaxonomyBadges } from '@/components/shared/TaxonomyBadges'
import { RatingBadge } from '@/features/threat-models/components/rating/RatingBadge'
import { targetCanvasId } from '@/features/dfd-editor/types/threat-analysis'
import type { DiagramNode, DataFlowEdge } from '@/features/dfd-editor/types'
import type { SharedCountermeasure, SharedTarget, SharedThreat, ThreatAnalysisData } from '@/features/organization/types/organization'

export interface DiagramData {
  id: string | number
  name: string
  canvasData?: {
    nodes?: DiagramNode[]
    edges?: DataFlowEdge[]
  }
}

const STATUS_CONFIG: Record<string, { label: string; icon: typeof CheckCircle2; color: string }> = {
  platform: { label: 'Platform', icon: CheckCircle2, color: 'text-green-600' },
  verified: { label: 'Verified', icon: CheckCircle2, color: 'text-green-600' },
  implemented: { label: 'Implemented', icon: CheckCircle2, color: 'text-emerald-600' },
  in_progress: { label: 'In progress', icon: Clock, color: 'text-orange-600' },
  planned: { label: 'Planned', icon: Clock, color: 'text-blue-600' },
  gap: { label: 'Gap', icon: XCircle, color: 'text-red-600' },
  waived: { label: 'Waived', icon: Info, color: 'text-gray-600' },
  decommissioned: { label: 'Decommissioned', icon: Info, color: 'text-gray-600' },
}

const THREAT_STATUS_CLASSES: Record<SharedThreat['status'], string> = {
  mitigated: 'bg-green-100 text-green-800',
  addressable: 'bg-yellow-100 text-yellow-800',
  exposed: 'bg-red-100 text-red-800',
}

const THREAT_STATUS_LABELS: Record<SharedThreat['status'], string> = {
  mitigated: 'Mitigated',
  addressable: 'Addressable',
  exposed: 'Exposed',
}

const THREAT_CARD_CLASSES: Record<SharedThreat['status'], string> = {
  mitigated: 'border-l-green-500 bg-green-50/50',
  addressable: 'border-l-yellow-500 bg-yellow-50/50',
  exposed: 'border-l-red-500 bg-red-50/50',
}

interface ReadOnlyThreatAnalysisViewProps {
  diagrams?: DiagramData[]
  threatAnalysisData?: ThreatAnalysisData
  className?: string
}

type TargetNameLookup = (target: SharedTarget) => string

/** "Whole system", or the target names in target order. */
function sharedThreatTargetsText(threat: SharedThreat, nameOf: TargetNameLookup): string {
  if (threat.wholeSystem || threat.targets.length === 0) return 'Whole system'
  return threat.targets.map(nameOf).join(', ')
}

function CountermeasureRow({ countermeasure, nameOf }: { countermeasure: SharedCountermeasure; nameOf: TargetNameLookup }) {
  const statusConfig = STATUS_CONFIG[countermeasure.status] || STATUS_CONFIG.gap
  const StatusIcon = statusConfig.icon
  const appliesTo = countermeasure.targets.length > 0 ? countermeasure.targets.map(nameOf).join(', ') : 'Whole system'

  return (
    <div className="flex items-center justify-between py-2 px-3 bg-muted/30 rounded-md gap-2">
      <div className="flex items-center gap-2 flex-1 min-w-0">
        <Shield className="h-4 w-4 text-muted-foreground flex-shrink-0" />
        <span className="font-mono text-xs font-semibold">{countermeasure.displayNumber}</span>
        <span className="text-sm truncate">{countermeasure.countermeasureName || 'Unnamed countermeasure'}</span>
        <span className="text-xs text-muted-foreground truncate">applies to {appliesTo}</span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {countermeasure.assignedOwnerEmail && (
          <span className="text-xs text-muted-foreground">{countermeasure.assignedOwnerEmail}</span>
        )}
        <Badge variant="outline" className={`text-xs ${statusConfig.color}`}>
          <StatusIcon className="h-3 w-3 mr-1" />
          {statusConfig.label}
        </Badge>
      </div>
    </div>
  )
}

function ThreatCard({ threat, nameOf }: { threat: SharedThreat; nameOf: TargetNameLookup }) {
  const [isOpen, setIsOpen] = useState(false)
  const diagramName = threat.targets.find((target) => target.dfdName)?.dfdName

  return (
    <Card className={`border-l-4 ${THREAT_CARD_CLASSES[threat.status] ?? THREAT_CARD_CLASSES.exposed}`}>
      <CardHeader className="cursor-pointer hover:bg-muted/20 transition-colors py-3" onClick={() => setIsOpen(!isOpen)}>
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            {isOpen ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            )}
            <AlertTriangle className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <CardTitle className="text-sm font-medium truncate">
                <span className="font-mono mr-2">{threat.displayNumber}</span>
                {threat.threatName || 'Unnamed threat'}
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Targets: {sharedThreatTargetsText(threat, nameOf)}
                {diagramName && ` (${diagramName})`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={2} size="sm" />
            <RatingBadge rating={threat.rating} size="sm" />
            <Badge variant="outline" className={`text-xs ${THREAT_STATUS_CLASSES[threat.status] ?? ''}`}>
              {THREAT_STATUS_LABELS[threat.status] ?? threat.status}
            </Badge>
            <span className="text-xs text-muted-foreground">
              {threat.countermeasures.length} control{threat.countermeasures.length === 1 ? '' : 's'}
            </span>
          </div>
        </div>
      </CardHeader>
      {isOpen && (
        <CardContent className="pt-0 pb-4">
          {threat.threatDescription && <p className="text-sm text-muted-foreground mb-4">{threat.threatDescription}</p>}
          {threat.countermeasures.length > 0 ? (
            <div className="space-y-2">
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Countermeasures ({threat.countermeasures.length})
              </h4>
              <div className="space-y-1">
                {threat.countermeasures.map((countermeasure) => (
                  <CountermeasureRow key={countermeasure.id} countermeasure={countermeasure} nameOf={nameOf} />
                ))}
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground italic">No countermeasures defined for this threat.</p>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export function ReadOnlyThreatAnalysisView({ diagrams, threatAnalysisData, className }: ReadOnlyThreatAnalysisViewProps) {
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards')
  const [filterDfd, setFilterDfd] = useState<string | null>(null)

  const safeDiagrams = useMemo(() => diagrams ?? [], [diagrams])
  const allThreats = useMemo(() => threatAnalysisData?.threats ?? [], [threatAnalysisData])

  // Canvas labels, used only when a target carries no name of its own.
  const canvasLabels = useMemo(() => {
    const labels = new Map<string, string>()
    for (const diagram of safeDiagrams) {
      for (const node of diagram.canvasData?.nodes ?? []) {
        const label = (node.data as { label?: string } | undefined)?.label
        if (label) labels.set(node.id, label)
      }
      for (const edge of diagram.canvasData?.edges ?? []) {
        const label = (edge as { id: string; data?: { label?: string } }).data?.label
        if (label) labels.set(edge.id, label)
      }
    }
    return labels
  }, [safeDiagrams])

  const nameOf: TargetNameLookup = (target) => {
    if (target.name) return target.name
    const canvasId = targetCanvasId(target)
    if (canvasId && canvasLabels.has(canvasId)) return canvasLabels.get(canvasId)!
    return target.type === 'flow' ? 'Unnamed flow' : `Unnamed ${target.type}`
  }

  const dfdOptions = useMemo(() => {
    const names = new Map<string, string>()
    for (const threat of allThreats) {
      for (const target of threat.targets) {
        if (target.dfdId && target.dfdName) names.set(target.dfdId, target.dfdName)
      }
    }
    if (names.size === 0) {
      for (const diagram of safeDiagrams) names.set(String(diagram.id), diagram.name)
    }
    return [...names.entries()].map(([id, name]) => ({ id, name }))
  }, [allThreats, safeDiagrams])

  const filteredThreats = useMemo(() => {
    const activeThreats = allThreats.filter((threat) => isActiveThreat(threat.triageStatus as TriageStatus))
    if (!filterDfd) return activeThreats
    return activeThreats.filter((threat) => threat.targets.some((target) => target.dfdId === filterDfd))
  }, [allThreats, filterDfd])

  const stats = useMemo(() => {
    const counts = { exposed: 0, addressable: 0, mitigated: 0 }
    for (const threat of filteredThreats) counts[threat.status] = (counts[threat.status] ?? 0) + 1
    return { ...counts, total: filteredThreats.length }
  }, [filteredThreats])

  if (allThreats.length === 0) {
    return (
      <div className={`flex flex-col items-center justify-center py-12 ${className}`}>
        <Shield className="h-12 w-12 text-muted-foreground/50 mb-4" />
        <h3 className="text-lg font-medium mb-2">No Threats Identified</h3>
        <p className="text-muted-foreground text-sm text-center max-w-md">
          No threats have been identified for this threat model yet. Threats are generated when components are added to
          the diagrams.
        </p>
      </div>
    )
  }

  return (
    <div className={className}>
      <div className="flex items-center justify-between mb-4 px-4 py-2 bg-muted/30 rounded-lg">
        <div className="flex items-center gap-4">
          <h2 className="font-semibold">Threat Analysis</h2>
          {dfdOptions.length > 1 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Filter by diagram:</span>
              <select
                value={filterDfd || ''}
                onChange={(event) => setFilterDfd(event.target.value || null)}
                className="text-sm border rounded-md px-2 py-1 bg-background"
              >
                <option value="">All diagrams</option>
                {dfdOptions.map((dfd) => (
                  <option key={dfd.id} value={dfd.id}>
                    {dfd.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm">
            {stats.exposed > 0 && (
              <Badge variant="outline" className="bg-red-100 text-red-800">
                {stats.exposed} exposed
              </Badge>
            )}
            {stats.addressable > 0 && (
              <Badge variant="outline" className="bg-yellow-100 text-yellow-800">
                {stats.addressable} addressable
              </Badge>
            )}
            {stats.mitigated > 0 && (
              <Badge variant="outline" className="bg-green-100 text-green-800">
                {stats.mitigated} mitigated
              </Badge>
            )}
          </div>
          <div className="flex items-center rounded-lg border bg-background p-1">
            <Button
              variant={viewMode === 'cards' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('cards')}
              className="rounded-md px-3 h-7 text-xs"
            >
              Cards
            </Button>
            <Button
              variant={viewMode === 'table' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('table')}
              className="rounded-md px-3 h-7 text-xs"
            >
              Table
            </Button>
          </div>
        </div>
      </div>

      {viewMode === 'cards' ? (
        <div className="space-y-3 px-4">
          {filteredThreats.map((threat) => (
            <ThreatCard key={threat.id} threat={threat} nameOf={nameOf} />
          ))}
        </div>
      ) : (
        <div className="px-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">#</TableHead>
                <TableHead>Threat</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Classifications</TableHead>
                <TableHead>Rating</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Controls</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredThreats.map((threat) => {
                const gaps = threat.countermeasures.filter((countermeasure) => countermeasure.status === 'gap').length
                return (
                  <TableRow key={threat.id}>
                    <TableCell className="font-mono text-xs font-semibold">{threat.displayNumber}</TableCell>
                    <TableCell className="font-medium">{threat.threatName || 'Unnamed threat'}</TableCell>
                    <TableCell className="text-sm">{sharedThreatTargetsText(threat, nameOf)}</TableCell>
                    <TableCell>
                      <TaxonomyBadges entries={threat.taxonomyEntries} maxVisible={3} />
                    </TableCell>
                    <TableCell>
                      <RatingBadge rating={threat.rating} size="sm" />
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-xs ${THREAT_STATUS_CLASSES[threat.status] ?? ''}`}>
                        {THREAT_STATUS_LABELS[threat.status] ?? threat.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      <span className="font-mono text-xs">
                        {threat.countermeasures.map((countermeasure) => countermeasure.displayNumber).join(', ') || 'None'}
                      </span>
                      {gaps > 0 && <span className="text-red-600 ml-1 text-xs">({gaps} gaps)</span>}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
