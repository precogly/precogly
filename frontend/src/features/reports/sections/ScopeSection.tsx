import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportMetadata, ReportScope } from '@/features/reports/types/report'
import type { SectionDepth } from '../reportConfig'
import {
  ASSUMPTION_VALIDITY_COLORS,
  assumptionTopicLabel,
  assumptionValidityLabel,
  formatReportDate,
  methodologiesText,
} from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ScopeSectionProps {
  scope: ReportScope
  depth: SectionDepth
  /** For the methodologies line; optional so older callers still work. */
  metadata?: ReportMetadata
}

const RELATION_TYPE_LABELS: Record<string, string> = {
  'depends-on': 'depends on',
  'subsystem-of': 'is a subsystem of',
  'related-to': 'is related to',
  'superseded-by': 'is superseded by',
}

/** Scope description, methodologies, assumptions as rows with validity (plan step 9), out of scope and related models. */
export function ScopeSection({ scope, depth, metadata }: ScopeSectionProps) {
  const methodologies = methodologiesText(metadata?.methodologies)
  const blueprintNames = new Set(scope.assumptions.map((assumption) => assumption.blueprint).filter(Boolean))
  const showBlueprint = blueprintNames.size > 1

  return (
    <ReportSection title="Scope & Assumptions">
      <div className="space-y-4">
        {scope.description && (
          <div>
            <h4 className="font-medium mb-1">Description</h4>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">{scope.description}</p>
          </div>
        )}

        {methodologies && (
          <div className="text-sm">
            <span className="font-medium">Methodologies:</span> {methodologies}
          </div>
        )}

        {scope.assumptions.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Assumptions ({scope.assumptions.length})</h4>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Assumption</TableHead>
                  <TableHead>Topic</TableHead>
                  <TableHead>Validity</TableHead>
                  <TableHead>Owner</TableHead>
                  {depth === 'full' && <TableHead>Validation</TableHead>}
                  {showBlueprint && <TableHead>Blueprint</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {scope.assumptions.map((assumption) => (
                  <TableRow key={assumption.id}>
                    <TableCell className="text-sm">
                      {assumption.description}
                      {depth === 'full' && assumption.impact && (
                        <div className="text-xs text-muted-foreground mt-0.5">Impact: {assumption.impact}</div>
                      )}
                    </TableCell>
                    <TableCell>{assumptionTopicLabel(assumption.topic)}</TableCell>
                    <TableCell>
                      <Badge className={ASSUMPTION_VALIDITY_COLORS[assumption.validity] || ''}>
                        {assumptionValidityLabel(assumption.validity)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{assumption.owner}</TableCell>
                    {depth === 'full' && (
                      <TableCell className="text-xs text-muted-foreground">
                        {[assumption.validationMethod, formatReportDate(assumption.validationDate)]
                          .filter(Boolean)
                          .join(', ')}
                      </TableCell>
                    )}
                    {showBlueprint && <TableCell className="text-sm">{assumption.blueprint}</TableCell>}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {depth === 'full' && scope.outOfScopeItems.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Out of Scope ({scope.outOfScopeItems.length})</h4>
            <div className="space-y-1">
              {scope.outOfScopeItems.map((item) => (
                <div key={item.id} className="text-sm">
                  <span className="font-medium">{item.name}</span>
                  {item.reason && <span className="text-muted-foreground">: {item.reason}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {scope.referencedModels.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Related Models</h4>
            <div className="flex flex-wrap gap-2">
              {scope.referencedModels.map((model) => (
                <Badge key={model.id} variant="outline">
                  {RELATION_TYPE_LABELS[model.relationType] ?? model.relationType} {model.name}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>
    </ReportSection>
  )
}
