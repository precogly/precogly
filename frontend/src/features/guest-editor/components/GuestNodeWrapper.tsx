import { memo, type ComponentType } from 'react'
import { EdgeLabelRenderer, type EdgeProps, type NodeProps } from '@xyflow/react'
import { useGuestEditor } from '../context/GuestEditorContext'

// Import original node components
import { ProcessNode } from '@/features/dfd-editor/components/nodes/ProcessNode'
import { DataStoreNode } from '@/features/dfd-editor/components/nodes/DataStoreNode'
import { HumanActorNode } from '@/features/dfd-editor/components/nodes/HumanActorNode'
import { SystemActorNode } from '@/features/dfd-editor/components/nodes/SystemActorNode'
import { TrustZoneNode } from '@/features/dfd-editor/components/nodes/TrustZoneNode'
import { SystemScopeNode } from '@/features/dfd-editor/components/nodes/SystemScopeNode'
import { StickyNoteNode } from '@/features/dfd-editor/components/nodes/StickyNoteNode'
import { TableNode } from '@/features/dfd-editor/components/nodes/TableNode'
import type { DiagramNodeType } from '@/features/dfd-editor/types'
import { DataFlowEdge as DataFlowEdgeComponent } from '@/features/dfd-editor/components/edges/DataFlowEdge'
import { TrustBoundaryEdge as TrustBoundaryEdgeComponent } from '@/features/dfd-editor/components/edges/TrustBoundaryEdge'

function ThreatBadge({ count }: { count: number }) {
  if (count === 0) return null
  return (
    <div
      className="absolute -top-2 -right-2 z-10 flex items-center justify-center min-w-[20px] h-5 px-1 rounded-full bg-red-500 text-white text-xs font-bold shadow-sm"
      style={{ pointerEvents: 'none' }}
    >
      {count}
    </div>
  )
}

function withThreatBadge<P extends NodeProps>(NodeComponent: ComponentType<P>) {
  const WrappedNode = memo(function WrappedNode(props: P) {
    const guestEditor = useGuestEditor()
    const count = guestEditor?.getThreatCount(props.id) ?? 0

    return (
      <div className="relative w-full h-full">
        <ThreatBadge count={count} />
        <NodeComponent {...props} />
      </div>
    )
  })
  return WrappedNode
}

// Wrapped node types with threat badges
export const guestNodeTypes = {
  process: withThreatBadge(ProcessNode),
  datastore: withThreatBadge(DataStoreNode),
  humanActor: withThreatBadge(HumanActorNode),
  systemActor: withThreatBadge(SystemActorNode),
  trustZone: withThreatBadge(TrustZoneNode),
  systemScope: withThreatBadge(SystemScopeNode),
  stickyNote: StickyNoteNode,
  table: TableNode,
  // `satisfies` makes a missing node type a build error. React Flow's own
  // behaviour for an unregistered type is to silently substitute its default
  // node, which renders as a small box containing the label and reads as a
  // broken component rather than a missing registration.
} as const satisfies Record<DiagramNodeType, unknown>

// Edge wrapper that adds a threat count badge
function withEdgeThreatBadge<P extends EdgeProps>(EdgeComponent: ComponentType<P>) {
  const WrappedEdge = memo(function WrappedEdge(props: P) {
    const guestEditor = useGuestEditor()
    const count = guestEditor?.getThreatCount(props.id) ?? 0

    return (
      <>
        <EdgeComponent {...props} />
        {count > 0 && (
          <EdgeLabelRenderer>
            <div
              data-id={props.id}
              className="absolute pointer-events-none nodrag nopan"
              style={{
                left: (props.sourceX + props.targetX) / 2,
                top: (props.sourceY + props.targetY) / 2 - 20,
                transform: 'translate(-50%, -50%)',
              }}
            >
              <div className="flex items-center justify-center min-w-[20px] h-5 px-1 rounded-full bg-red-500 text-white text-xs font-bold shadow-sm">
                {count}
              </div>
            </div>
          </EdgeLabelRenderer>
        )}
      </>
    )
  })
  return WrappedEdge
}

// Wrapped edge types with threat badges
export const guestEdgeTypes = {
  dataFlow: withEdgeThreatBadge(DataFlowEdgeComponent),
  trustBoundary: TrustBoundaryEdgeComponent,
} as const
