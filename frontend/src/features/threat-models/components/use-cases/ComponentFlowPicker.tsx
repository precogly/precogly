/**
 * Pick components and flows of a model. Grouped by blueprint only when the
 * model has more than one; a search box narrows both lists. Any component
 * category can be picked, data stores included.
 */

import { useMemo, useState } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import { useFlows } from '@/features/threat-models/api/flows'
import { useBlueprints } from '@/features/threat-models/api/threat-models'
import { groupByBlueprint, showsBlueprintChoice } from '@/features/threat-models/components/workspace/blueprint-utils'
import { formatFlowLabel } from './use-case-utils'

interface ComponentFlowPickerProps {
  threatModelId: string
  componentIds: number[]
  flowIds: number[]
  onChange: (selection: { componentIds: number[]; flowIds: number[] }) => void
  disabled?: boolean
}

interface PickerRow {
  key: string
  id: number
  kind: 'component' | 'flow'
  label: string
  blueprint: number
}

function toggle(ids: number[], id: number): number[] {
  return ids.includes(id) ? ids.filter((current) => current !== id) : [...ids, id]
}

export function ComponentFlowPicker({ threatModelId, componentIds, flowIds, onChange, disabled }: ComponentFlowPickerProps) {
  const { data: components = [] } = useAnalysisComponents(threatModelId)
  const { data: flows = [] } = useFlows({ threatModel: threatModelId })
  const { data: blueprints = [] } = useBlueprints(threatModelId)
  const [search, setSearch] = useState('')

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const componentRows: PickerRow[] = components.map((component) => ({
      key: `component-${component.id}`,
      id: component.id,
      kind: 'component',
      label: component.name,
      blueprint: component.blueprint,
    }))
    const flowRows: PickerRow[] = flows.map((flow) => ({
      key: `flow-${flow.id}`,
      id: flow.id,
      kind: 'flow',
      label: formatFlowLabel({
        name: flow.label,
        sourceName: flow.sourceComponentName,
        destinationName: flow.destComponentName,
      }),
      blueprint: flow.blueprint,
    }))
    return [...componentRows, ...flowRows].filter((row) => !needle || row.label.toLowerCase().includes(needle))
  }, [components, flows, search])

  const grouped = showsBlueprintChoice(blueprints)
  const groups = grouped
    ? groupByBlueprint(rows, blueprints)
    : [{ blueprint: null, items: rows }]

  const selectedCount = componentIds.length + flowIds.length

  const renderRows = (items: PickerRow[]) => {
    const itemComponents = items.filter((row) => row.kind === 'component')
    const itemFlows = items.filter((row) => row.kind === 'flow')
    const renderRow = (row: PickerRow) => {
      const checked = row.kind === 'component' ? componentIds.includes(row.id) : flowIds.includes(row.id)
      return (
        <label key={row.key} className="flex cursor-pointer items-center gap-2 py-0.5 text-sm">
          <Checkbox
            checked={checked}
            disabled={disabled}
            onCheckedChange={() =>
              onChange(
                row.kind === 'component'
                  ? { componentIds: toggle(componentIds, row.id), flowIds }
                  : { componentIds, flowIds: toggle(flowIds, row.id) }
              )
            }
          />
          <span className="truncate">{row.label}</span>
        </label>
      )
    }
    return (
      <>
        {itemComponents.length > 0 && (
          <div>
            <div className="text-[11px] font-medium uppercase text-muted-foreground">Components</div>
            {itemComponents.map(renderRow)}
          </div>
        )}
        {itemFlows.length > 0 && (
          <div>
            <div className="text-[11px] font-medium uppercase text-muted-foreground">Flows</div>
            {itemFlows.map(renderRow)}
          </div>
        )}
      </>
    )
  }

  return (
    <div className="space-y-1.5" data-testid="component-flow-picker">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Components and flows</div>
        {selectedCount > 0 && <span className="text-xs text-muted-foreground">{selectedCount} selected</span>}
      </div>
      <Input
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="Search components and flows"
        aria-label="Search components and flows"
        className="h-8"
      />
      <div className="max-h-48 space-y-2 overflow-y-auto rounded-md border p-2">
        {rows.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            {components.length + flows.length === 0 ? 'This model has no components or flows yet.' : 'Nothing matches.'}
          </p>
        ) : (
          groups.map((group) => (
            <div key={group.blueprint?.id ?? 'all'} className="space-y-1">
              {grouped && <div className="text-xs font-semibold">{group.blueprint?.name ?? 'No blueprint'}</div>}
              {renderRows(group.items)}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
