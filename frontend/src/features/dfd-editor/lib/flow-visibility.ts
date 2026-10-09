/**
 * The flow type filter (the "physical view", plan F22) and the per-type
 * drawing of flow edges.
 *
 * The canvas root stores `visibleFlowTypes`. A missing list means every type
 * is visible, which is what every diagram saved before this change has.
 */

import { FLOW_TYPES, type FlowType } from '@/types/domain'

const ALL_FLOW_TYPES: FlowType[] = FLOW_TYPES.map((entry) => entry.value)

/** Whether a flow of `flowType` is drawn under the filter. Missing list means all visible. */
export function isFlowTypeVisible(
  flowType: FlowType,
  visibleFlowTypes: readonly FlowType[] | null | undefined
): boolean {
  if (!visibleFlowTypes) return true
  return visibleFlowTypes.includes(flowType)
}

/** Whether the filter hides at least one type. */
export function isFlowFilterActive(visibleFlowTypes: readonly FlowType[] | null | undefined): boolean {
  if (!visibleFlowTypes) return false
  return ALL_FLOW_TYPES.some((flowType) => !visibleFlowTypes.includes(flowType))
}

/**
 * The list after ticking or unticking one type. The result is `undefined`
 * (every type visible, nothing stored) as soon as every type is ticked, so a
 * diagram with no filter stays free of the key.
 */
export function toggleFlowTypeVisibility(
  visibleFlowTypes: readonly FlowType[] | null | undefined,
  flowType: FlowType
): FlowType[] | undefined {
  const current = visibleFlowTypes ? [...visibleFlowTypes] : [...ALL_FLOW_TYPES]
  const next = current.includes(flowType)
    ? current.filter((entry) => entry !== flowType)
    : [...current, flowType]
  const everyTypeVisible = ALL_FLOW_TYPES.every((entry) => next.includes(entry))
  if (everyTypeVisible) return undefined
  // Keep the spec order so the stored list reads the same whatever the click order.
  return ALL_FLOW_TYPES.filter((entry) => next.includes(entry))
}

/** A short summary for the toolbar: "All flows" or the ticked type names. */
export function describeVisibleFlowTypes(visibleFlowTypes: readonly FlowType[] | null | undefined): string {
  if (!isFlowFilterActive(visibleFlowTypes)) return 'All flows'
  const names = FLOW_TYPES.filter((entry) => visibleFlowTypes?.includes(entry.value)).map((entry) =>
    entry.label.replace(/ flow$/, '')
  )
  if (names.length === 0) return 'No flows'
  return names.join(', ')
}

/** The short type name shown on the canvas ("Signal", "Control"). */
export function flowTypeShortLabel(flowType: FlowType): string {
  const entry = FLOW_TYPES.find((candidate) => candidate.value === flowType)
  return (entry?.label ?? flowType).replace(/ flow$/, '')
}

export interface FlowTypeStyle {
  /** SVG dash pattern; `undefined` draws a solid line. */
  strokeDasharray?: string
  strokeWidth: number
  /** Tailwind classes for the small type chip under the label. */
  chipClassName: string
}

/**
 * How each flow type is drawn. Data flows keep today's look (solid, or the
 * short animated dash); every other type gets its own dash pattern and a
 * chip so a signal is told from a data flow at a glance.
 */
export const FLOW_TYPE_STYLES: Record<FlowType, FlowTypeStyle> = {
  data: { strokeWidth: 2, chipClassName: 'bg-gray-100 text-gray-700 border-gray-200' },
  message: { strokeDasharray: '8 4', strokeWidth: 2, chipClassName: 'bg-sky-100 text-sky-700 border-sky-200' },
  event: { strokeDasharray: '2 4', strokeWidth: 2, chipClassName: 'bg-violet-100 text-violet-700 border-violet-200' },
  control: {
    strokeDasharray: '12 4 2 4',
    strokeWidth: 2,
    chipClassName: 'bg-amber-100 text-amber-800 border-amber-200',
  },
  process: { strokeDasharray: '16 6', strokeWidth: 2, chipClassName: 'bg-teal-100 text-teal-700 border-teal-200' },
  signal: { strokeDasharray: '4 4', strokeWidth: 2, chipClassName: 'bg-orange-100 text-orange-700 border-orange-200' },
  financial: {
    strokeDasharray: '10 3 3 3',
    strokeWidth: 2,
    chipClassName: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  },
  energy: { strokeWidth: 3, chipClassName: 'bg-yellow-100 text-yellow-800 border-yellow-300' },
  physical: { strokeDasharray: '20 5', strokeWidth: 3, chipClassName: 'bg-stone-200 text-stone-800 border-stone-300' },
}

/** Whether the canvas shows a type chip for the flow: every type except `data`. */
export function showsFlowTypeChip(flowType: FlowType): boolean {
  return flowType !== 'data'
}
