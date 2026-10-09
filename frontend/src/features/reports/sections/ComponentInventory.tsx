import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { ReportComponent, ReportComponents, ReportFlow } from '@/features/reports/types/report'
import { isAuthenticated } from '@/lib/authentication'
import { componentKindLabel, defaultKindForCategory, flowTypeLabel, requirementListText } from '../utils/labels'
import { ReportSection } from '../ReportSection'

interface ComponentInventoryProps {
  components: ReportComponents
  dataFlows: ReportFlow[]
}

/** The kind column: the stored kind when the payload has one, else the default for the category. */
function componentKindText(component: Pick<ReportComponent, 'kind' | 'category'>): string {
  return componentKindLabel(component.kind ?? defaultKindForCategory(component.category))
}

function ComponentTable({ components, label }: { components: ReportComponent[]; label: string }) {
  if (components.length === 0) return null

  return (
    <div>
      <h4 className="font-medium mb-2">
        {label} ({components.length})
      </h4>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Technology</TableHead>
            <TableHead>Provider</TableHead>
            <TableHead>Zone</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {components.map((component) => (
            <TableRow key={component.id}>
              <TableCell className="font-medium">{component.name}</TableCell>
              <TableCell>{componentKindText(component)}</TableCell>
              <TableCell>{component.componentType}</TableCell>
              <TableCell>{component.provider || ''}</TableCell>
              <TableCell>{component.zone || 'No zone'}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

/** Components by category with kind and zone, then flows with type and the authentication helper (I5). */
export function ComponentInventory({ components, dataFlows }: ComponentInventoryProps) {
  return (
    <ReportSection title="Components & Flows">
      <div className="space-y-4">
        <ComponentTable components={components.processes} label="Processes" />
        <ComponentTable components={components.dataStores} label="Data Stores" />
        <ComponentTable components={components.humanActors} label="Human Actors" />
        <ComponentTable components={components.systemActors} label="System Actors" />

        {dataFlows.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Flows ({dataFlows.length})</h4>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Encrypted</TableHead>
                  <TableHead>Authenticated</TableHead>
                  <TableHead>Crosses boundary</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dataFlows.map((flow) => (
                  <TableRow key={flow.id}>
                    <TableCell className="font-medium">
                      {flow.label}
                      {flow.hasSensitiveData && (
                        <span className="ml-1 text-[10px] text-muted-foreground">(sensitive data)</span>
                      )}
                    </TableCell>
                    <TableCell>{flowTypeLabel(flow.flowType)}</TableCell>
                    <TableCell>{flow.source || ''}</TableCell>
                    <TableCell>{flow.destination || ''}</TableCell>
                    <TableCell>{flow.protocol || ''}</TableCell>
                    <TableCell>{flow.encrypted ? 'Yes' : 'No'}</TableCell>
                    <TableCell title={requirementListText(flow.authentication)}>
                      {isAuthenticated(flow.authentication) ? `Yes (${flow.authentication.join(', ')})` : 'No'}
                    </TableCell>
                    <TableCell>{flow.crossesBoundary ? 'Yes' : 'No'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </ReportSection>
  )
}
