import { useState } from 'react'
import { ChevronDown, ChevronUp, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ReadOnlyDFDViewer } from '@/components/shared/ReadOnlyDFDViewer'
import type { ReportArchitecture } from '@/features/reports/types/report'
import { boundaryCrossingRequirementsText, boundaryTypeLabel, zoneTrustLevelText, zoneTypeLabel } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ArchitectureSectionProps {
  architecture: ReportArchitecture
}

/** Diagrams, then zones with their type and level, then boundaries with their type and crossing requirements (plan 11.6). */
export function ArchitectureSection({ architecture }: ArchitectureSectionProps) {
  const primaryDfdId = architecture.dfds.find((dfd) => dfd.isPrimary)?.id ?? null
  const [expandedDFDId, setExpandedDFDId] = useState<string | null>(primaryDfdId)

  return (
    <ReportSection title="Architecture">
      <div className="space-y-4">
        {architecture.dfds.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Diagrams</h4>
            <div className="space-y-3">
              {architecture.dfds.map((dfd) => {
                const isExpanded = expandedDFDId === dfd.id

                return (
                  <div key={dfd.id} className="border rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedDFDId(isExpanded ? null : dfd.id)}
                      className="w-full flex items-center justify-between p-4 bg-muted/30 hover:bg-muted/50 transition-colors text-left"
                    >
                      <div>
                        <h4 className="font-medium">
                          {dfd.name}
                          {dfd.isPrimary ? (
                            <span className="ml-2 text-xs text-green-600 font-medium">(Primary)</span>
                          ) : (
                            <span className="ml-2 text-xs text-muted-foreground">(Reference)</span>
                          )}
                        </h4>
                        <p className="text-sm text-muted-foreground mt-1">
                          {dfd.nodeCount} nodes, {dfd.edgeCount} flows
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-muted-foreground">
                          {isExpanded ? 'Hide diagram' : 'View diagram'}
                        </span>
                        {isExpanded ? (
                          <ChevronUp className="h-5 w-5 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="h-5 w-5 text-muted-foreground" />
                        )}
                      </div>
                    </button>

                    {isExpanded && dfd.canvasData && (
                      <div className="border-t">
                        <div className="p-2 bg-muted/20 flex items-center justify-between">
                          <span className="text-xs text-muted-foreground">Pan and zoom to explore the diagram</span>
                          <Button variant="ghost" size="sm" onClick={() => setExpandedDFDId(null)}>
                            <X className="h-4 w-4 mr-1" />
                            Close
                          </Button>
                        </div>
                        <ReadOnlyDFDViewer canvasData={dfd.canvasData} className="h-[500px] w-full" />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {architecture.zones.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Zones ({architecture.zones.length})</h4>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Trust level</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {architecture.zones.map((zone) => (
                  <TableRow key={zone.id}>
                    <TableCell className="font-medium">{zone.name}</TableCell>
                    <TableCell>{zoneTypeLabel(zone.zoneType)}</TableCell>
                    <TableCell className="text-right">{zoneTrustLevelText(zone)}</TableCell>
                    <TableCell className="text-muted-foreground">{zone.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {architecture.boundaries.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Boundaries ({architecture.boundaries.length})</h4>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Between</TableHead>
                  <TableHead>Crossing requirements</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {architecture.boundaries.map((boundary) => (
                  <TableRow key={boundary.id}>
                    <TableCell className="font-medium">
                      {boundary.label}
                      {boundary.description && (
                        <div className="text-xs text-muted-foreground">{boundary.description}</div>
                      )}
                    </TableCell>
                    <TableCell>{boundaryTypeLabel(boundary.boundaryType)}</TableCell>
                    <TableCell>
                      {boundary.zoneA} and {boundary.zoneB}
                    </TableCell>
                    <TableCell className="text-sm">{boundaryCrossingRequirementsText(boundary)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {architecture.referenceImages.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Reference Images</h4>
            <div className="space-y-1">
              {architecture.referenceImages.map((image) => (
                <div key={image.id} className="text-sm">
                  <span className="font-medium">{image.filename}</span>
                  {image.description && <span className="text-muted-foreground">: {image.description}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </ReportSection>
  )
}
