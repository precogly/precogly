/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useMemo, type ReactNode } from 'react'
import type { FlowType } from '@/types/domain'
import type { DFDNotationStyle } from '../types/notation'

/**
 * Canvas-wide display settings read by the node and edge renderers: the
 * notation style and the flow type filter (the "physical view", plan F22).
 * Both live on the canvas root (`notationStyle`, `visibleFlowTypes`), so the
 * editor, the guest editor and the read-only viewer pass the same values.
 */
interface DFDNotationContextValue {
  notationStyle: DFDNotationStyle
  /** The flow types drawn; missing means every type. */
  visibleFlowTypes?: FlowType[]
}

const DFDNotationContext = createContext<DFDNotationContextValue>({
  notationStyle: 'dfd3',
})

export function DFDNotationProvider({
  notationStyle,
  visibleFlowTypes,
  children,
}: {
  notationStyle: DFDNotationStyle
  visibleFlowTypes?: FlowType[]
  children: ReactNode
}) {
  const value = useMemo(() => ({ notationStyle, visibleFlowTypes }), [notationStyle, visibleFlowTypes])
  return <DFDNotationContext.Provider value={value}>{children}</DFDNotationContext.Provider>
}

export function useDFDNotation(): DFDNotationContextValue {
  return useContext(DFDNotationContext)
}
