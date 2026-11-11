import { StickyNoteNode } from '@/features/dfd-editor/components/nodes/StickyNoteNode'
import { TableNode } from '@/features/dfd-editor/components/nodes/TableNode'
import type { DiagramNodeType } from '@/features/dfd-editor/types'
import {
  GuestProcessNode,
  GuestDataStoreNode,
  GuestHumanActorNode,
  GuestSystemActorNode,
  GuestTrustZoneNode,
  GuestSystemScopeNode,
  GuestDataFlowEdge,
  GuestTrustBoundaryEdge,
} from './GuestNodeWrapper'

// Wrapped node types with threat badges
export const guestNodeTypes = {
  process: GuestProcessNode,
  datastore: GuestDataStoreNode,
  humanActor: GuestHumanActorNode,
  systemActor: GuestSystemActorNode,
  trustZone: GuestTrustZoneNode,
  systemScope: GuestSystemScopeNode,
  stickyNote: StickyNoteNode,
  table: TableNode,
  // `satisfies` makes a missing node type a build error. React Flow's own
  // behaviour for an unregistered type is to silently substitute its default
  // node, which renders as a small box containing the label and reads as a
  // broken component rather than a missing registration.
} as const satisfies Record<DiagramNodeType, unknown>

// Wrapped edge types with threat badges
export const guestEdgeTypes = {
  dataFlow: GuestDataFlowEdge,
  // Boundaries take threats too (plan 11.9).
  trustBoundary: GuestTrustBoundaryEdge,
} as const
