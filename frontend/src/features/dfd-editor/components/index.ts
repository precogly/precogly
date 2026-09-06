// Node components
export * from './nodes'
import { ProcessNode } from './nodes/ProcessNode'
import { DataStoreNode } from './nodes/DataStoreNode'
import { HumanActorNode } from './nodes/HumanActorNode'
import { SystemActorNode } from './nodes/SystemActorNode'
import { TrustZoneNode } from './nodes/TrustZoneNode'
import { SystemScopeNode } from './nodes/SystemScopeNode'
import { StickyNoteNode } from './nodes/StickyNoteNode'

// Edge components
export * from './edges'
import { DataFlowEdge } from './edges/DataFlowEdge'
import { TrustBoundaryEdge } from './edges/TrustBoundaryEdge'

// Panel components
export * from './panels'

// Other components
export { TemplateBrowser } from './TemplateBrowser'
export { TechnologyCombobox } from './technology-combobox'

// Node type registry for React Flow
export const nodeTypes = {
  process: ProcessNode,
  datastore: DataStoreNode,
  humanActor: HumanActorNode,
  systemActor: SystemActorNode,
  trustZone: TrustZoneNode,
  systemScope: SystemScopeNode,
  stickyNote: StickyNoteNode,
} as const

// Edge type registry for React Flow
export const edgeTypes = {
  dataFlow: DataFlowEdge,
  trustBoundary: TrustBoundaryEdge,
} as const
