import { createContext, useContext, type ReactNode } from 'react'
import type { DiagramNode, DiagramEdge } from '@/features/dfd-editor/types'
import type {
  GuestSessionMetadata,
  GuestSystemInfo,
  GuestDataAsset,
  GuestAssumption,
  GuestOutOfScopeItem,
  GuestSystemContext,
} from '../types'
import type { GuestModel } from '../hooks/useGuestModel'

export interface GuestEditorContextType extends GuestModel {
  // Diagram data (read-only from context consumers)
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  title: string

  // What the opened file carried that is not shown (G8)
  hiddenBlueprintCount: number
  hiddenElementCount: number

  // System Context state (read-only)
  session: GuestSessionMetadata
  systemInfo: GuestSystemInfo
  dataAssets: GuestDataAsset[]
  assumptions: GuestAssumption[]
  outOfScopeItems: GuestOutOfScopeItem[]

  // System Context operations
  updateSession: (updates: Partial<GuestSessionMetadata>) => void
  updateSystemInfo: (updates: Partial<GuestSystemInfo>) => void
  addDataAsset: (asset: Omit<GuestDataAsset, 'id'>) => void
  updateDataAsset: (assetId: string, updates: Partial<Omit<GuestDataAsset, 'id'>>) => void
  removeDataAsset: (assetId: string) => void
  addAssumption: (assumption: Omit<GuestAssumption, 'id'>) => void
  updateAssumption: (assumptionId: string, updates: Partial<Omit<GuestAssumption, 'id'>>) => void
  removeAssumption: (assumptionId: string) => void
  addOutOfScopeItem: (item: Omit<GuestOutOfScopeItem, 'id'>) => void
  updateOutOfScopeItem: (itemId: string, updates: Partial<Omit<GuestOutOfScopeItem, 'id'>>) => void
  removeOutOfScopeItem: (itemId: string) => void
  loadSystemContext: (context: GuestSystemContext) => void
  getSystemContext: () => GuestSystemContext
}

const GuestEditorContext = createContext<GuestEditorContextType | null>(null)

export function GuestEditorProvider({
  children,
  value,
}: {
  children: ReactNode
  value: GuestEditorContextType
}) {
  return (
    <GuestEditorContext.Provider value={value}>
      {children}
    </GuestEditorContext.Provider>
  )
}

export function useGuestEditor(): GuestEditorContextType | null {
  return useContext(GuestEditorContext)
}
