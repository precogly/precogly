/**
 * Read-only DFD viewer for shared/public views.
 * Displays a Data Flow Diagram without editing capabilities.
 */

import { forwardRef, useImperativeHandle, useRef } from 'react'
import { ReactFlow, Background, Controls, ReactFlowProvider, useReactFlow, type Edge, type Node } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { nodeTypes, edgeTypes } from '@/features/dfd-editor/components'
import { DFDNotationProvider } from '@/features/dfd-editor/context/DFDNotationContext'
import { DEFAULT_NOTATION } from '@/features/dfd-editor/types/notation'
import type { FlowType } from '@/types/domain'
import { captureDiagramImage } from '@/features/dfd-editor/lib/export-diagram-image'

// Flexible canvas data type that accepts the API response format
interface CanvasData {
  nodes?: unknown[]
  edges?: unknown[]
  notationStyle?: string
  /** The flow type filter saved with the diagram (plan F22); missing means every type. */
  visibleFlowTypes?: FlowType[]
}

interface ReadOnlyDFDViewerProps {
  canvasData: CanvasData
  className?: string
}

export interface ReadOnlyDFDViewerHandle {
  captureImage: () => Promise<Uint8Array>
}

const DFDViewerContent = forwardRef<ReadOnlyDFDViewerHandle, ReadOnlyDFDViewerProps>(function DFDViewerContent(
  { canvasData, className },
  ref,
) {
  const wrapperRef = useRef<HTMLDivElement>(null)
  const reactFlow = useReactFlow()
  const nodes = (canvasData.nodes ?? []) as Node[]
  const edges = (canvasData.edges ?? []) as Edge[]
  const notationStyle = (canvasData.notationStyle as 'dfd3' | 'yourdon') ?? DEFAULT_NOTATION

  useImperativeHandle(ref, () => ({
    captureImage: () => {
      if (!wrapperRef.current) {
        throw new Error('DFD viewer is not mounted')
      }

      return captureDiagramImage(
        wrapperRef.current,
        reactFlow.getNodes(),
        reactFlow.getViewport,
        reactFlow.setViewport,
        reactFlow.getNodesBounds,
      )
    },
  }), [reactFlow])

  return (
    <div ref={wrapperRef} className={className}>
      <DFDNotationProvider notationStyle={notationStyle} visibleFlowTypes={canvasData.visibleFlowTypes}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={2}
          // Disable all interactions except pan and zoom
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          panOnDrag
          zoomOnScroll
          zoomOnPinch
          preventScrolling
        >
          {/* SVG Definitions for edge markers */}
          <svg style={{ position: 'absolute', width: 0, height: 0 }}>
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280" />
              </marker>
            </defs>
          </svg>
          <Background gap={15} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </DFDNotationProvider>
    </div>
  )
})

export const ReadOnlyDFDViewer = forwardRef<ReadOnlyDFDViewerHandle, ReadOnlyDFDViewerProps>(function ReadOnlyDFDViewer(props, ref) {
  return (
    <ReactFlowProvider>
      <DFDViewerContent {...props} ref={ref} />
    </ReactFlowProvider>
  )
})
