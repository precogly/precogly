/**
 * Every target the model offers (components, flows, zones, boundaries), with
 * labels, keyed as `component:5`. Shared by the target picker and the page.
 */

import { useMemo } from 'react'
import { useAnalysisComponents, useZones } from '@/features/threat-models/api/components'
import { useFlows } from '@/features/threat-models/api/flows'
import { useBoundaries } from '@/features/threat-models/api/boundaries'
import type { TargetRef } from '@/features/threat-models/api/threats'
import type { TargetType } from '../../types/threat-analysis'
import { TARGET_TYPE_LABELS } from './analysis-selection'
import { boundaryLabel, flowLabel } from './hierarchy-utils'

export interface TargetOption {
  ref: TargetRef
  key: string
  label: string
  typeLabel: string
  blueprintId: number
}

const TYPE_ORDER: TargetType[] = ['component', 'flow', 'zone', 'boundary']

export function useModelTargets(threatModelId: string | null | undefined) {
  const components = useAnalysisComponents(threatModelId ?? null)
  const zones = useZones({ threatModel: threatModelId })
  const flows = useFlows({ threatModel: threatModelId })
  const boundaries = useBoundaries({ threatModel: threatModelId })

  const options = useMemo((): TargetOption[] => {
    const list: TargetOption[] = []
    for (const component of components.data ?? []) {
      list.push({
        ref: { type: 'component', id: component.id },
        key: `component:${component.id}`,
        label: component.name,
        typeLabel: TARGET_TYPE_LABELS.component,
        blueprintId: component.blueprint,
      })
    }
    for (const flow of flows.data ?? []) {
      list.push({
        ref: { type: 'flow', id: flow.id },
        key: `flow:${flow.id}`,
        label: flowLabel(flow),
        typeLabel: TARGET_TYPE_LABELS.flow,
        blueprintId: flow.blueprint,
      })
    }
    for (const zone of zones.data ?? []) {
      list.push({
        ref: { type: 'zone', id: zone.id },
        key: `zone:${zone.id}`,
        label: zone.name,
        typeLabel: TARGET_TYPE_LABELS.zone,
        blueprintId: zone.blueprint,
      })
    }
    for (const boundary of boundaries.data ?? []) {
      list.push({
        ref: { type: 'boundary', id: boundary.id },
        key: `boundary:${boundary.id}`,
        label: boundaryLabel(boundary),
        typeLabel: TARGET_TYPE_LABELS.boundary,
        blueprintId: boundary.blueprint,
      })
    }
    list.sort(
      (left, right) =>
        TYPE_ORDER.indexOf(left.ref.type) - TYPE_ORDER.indexOf(right.ref.type) ||
        left.label.localeCompare(right.label)
    )
    return list
  }, [components.data, flows.data, zones.data, boundaries.data])

  const byKey = useMemo(() => new Map(options.map((option) => [option.key, option])), [options])

  return {
    options,
    byKey,
    isLoading: components.isLoading || zones.isLoading || flows.isLoading || boundaries.isLoading,
  }
}

