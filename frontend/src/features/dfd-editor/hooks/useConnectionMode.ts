import { useCallback, useState, useEffect } from 'react'
import { addEdge } from '@xyflow/react'
import type { XYPosition } from '@xyflow/react'
import type { DiagramNode, DiagramEdge, DataFlowEdge } from '../types'
import { DEFAULT_FLOW_TYPE } from '@/types/domain'

/**
 * Manages click-to-connect interaction mode.
 * Returns connection state and handlers for composing into DFDEditor.
 */
export function useConnectionMode({
  nodes,
  edges,
  setEdges,
  screenToFlowPosition,
}: {
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  setEdges: React.Dispatch<React.SetStateAction<DiagramEdge[]>>
  screenToFlowPosition: (position: { x: number; y: number }) => XYPosition
}) {
  const [connectionMode, setConnectionMode] = useState(false)
  const [connectionSourceId, setConnectionSourceId] = useState<string | null>(null)
  const [mousePosition, setMousePosition] = useState<XYPosition | null>(null)

  // Clear connection source when connection mode is turned off
  useEffect(() => {
    if (!connectionMode) {
      setConnectionSourceId(null)
      setMousePosition(null)
    }
  }, [connectionMode])

  // Calculate absolute position of a node (accounting for parent offsets)
  const getAbsolutePosition = useCallback(
    (nodeId: string): XYPosition | null => {
      const node = nodes.find((n) => n.id === nodeId)
      if (!node) return null

      let x = node.position.x
      let y = node.position.y

      // Traverse up the parent chain to accumulate offsets
      let currentNode = node
      while (currentNode.parentId) {
        const parent = nodes.find((n) => n.id === currentNode.parentId)
        if (!parent) break
        x += parent.position.x
        y += parent.position.y
        currentNode = parent as DiagramNode
      }

      return { x, y }
    },
    [nodes]
  )

  // Smart handle selection based on absolute node positions
  // Also considers existing edges to avoid overlapping reverse connections
  const getSmartHandles = useCallback(
    (sourceId: string, targetId: string): { sourceHandle: string; targetHandle: string } => {
      const sourcePos = getAbsolutePosition(sourceId)
      const targetPos = getAbsolutePosition(targetId)

      if (!sourcePos || !targetPos) {
        return { sourceHandle: 'right-source', targetHandle: 'left-target' }
      }

      const dx = targetPos.x - sourcePos.x
      const dy = targetPos.y - sourcePos.y

      // Check if an edge already exists between these nodes (in either direction)
      const existingEdge = edges.find(
        (e) =>
          (e.source === sourceId && e.target === targetId) ||
          (e.source === targetId && e.target === sourceId)
      )

      // Determine primary and secondary axis based on relative positions
      const primaryIsHorizontal = Math.abs(dx) > Math.abs(dy)

      // If no existing edge, use primary axis (most direct route)
      if (!existingEdge) {
        if (primaryIsHorizontal) {
          if (dx > 0) {
            return { sourceHandle: 'right-source', targetHandle: 'left-target' }
          } else {
            return { sourceHandle: 'left-source', targetHandle: 'right-target' }
          }
        } else {
          if (dy > 0) {
            return { sourceHandle: 'bottom-source', targetHandle: 'top-target' }
          } else {
            return { sourceHandle: 'top-source', targetHandle: 'bottom-target' }
          }
        }
      }

      // An edge already exists - use secondary axis (perpendicular) to avoid overlap
      if (primaryIsHorizontal) {
        if (dy >= 0) {
          return { sourceHandle: 'bottom-source', targetHandle: 'top-target' }
        } else {
          return { sourceHandle: 'top-source', targetHandle: 'bottom-target' }
        }
      } else {
        if (dx >= 0) {
          return { sourceHandle: 'right-source', targetHandle: 'left-target' }
        } else {
          return { sourceHandle: 'left-source', targetHandle: 'right-target' }
        }
      }
    },
    [getAbsolutePosition, edges]
  )

  // Get the source node's absolute position for visual feedback
  const connectionSourcePosition = connectionSourceId
    ? getAbsolutePosition(connectionSourceId)
    : null

  /**
   * Handle node click in connection mode.
   * Returns true if the click was consumed (handled by connection mode).
   */
  const handleNodeClickForConnection = useCallback(
    (node: DiagramNode): boolean => {
      if (!connectionMode) return false

      // Only allow connecting process, datastore, humanActor, and systemActor nodes
      const connectableTypes = ['process', 'datastore', 'humanActor', 'systemActor']
      if (!connectableTypes.includes(node.type || '')) {
        return true // consume the click but don't connect
      }

      if (!connectionSourceId) {
        // First click: set as source
        setConnectionSourceId(node.id)
      } else if (connectionSourceId === node.id) {
        // Clicked same node: deselect
        setConnectionSourceId(null)
      } else {
        // Second click on different node: create edge
        const { sourceHandle, targetHandle } = getSmartHandles(connectionSourceId, node.id)

        const newEdge: DataFlowEdge = {
          id: `edge-${Date.now()}`,
          source: connectionSourceId,
          target: node.id,
          sourceHandle,
          targetHandle,
          type: 'dataFlow',
          animated: true,
          // A new flow is a data flow with no authentication recorded (plan 4.6).
          data: {
            label: '',
            flowType: DEFAULT_FLOW_TYPE,
            encrypted: false,
            authentication: [],
          },
        }

        setEdges((eds) => addEdge(newEdge, eds) as DiagramEdge[])
        // Clear source but stay in connection mode for chaining
        setConnectionSourceId(null)
      }
      return true
    },
    [connectionMode, connectionSourceId, getSmartHandles, setEdges]
  )

  // Track mouse position for connection line overlay
  const handleMouseMove = useCallback(
    (event: React.MouseEvent) => {
      if (connectionMode && connectionSourceId) {
        const position = screenToFlowPosition({
          x: event.clientX,
          y: event.clientY,
        })
        setMousePosition(position)
      }
    },
    [connectionMode, connectionSourceId, screenToFlowPosition]
  )

  // Handle pane click in connection mode: clear source selection
  const handlePaneClickForConnection = useCallback(() => {
    if (connectionMode) {
      setConnectionSourceId(null)
    }
  }, [connectionMode])

  return {
    connectionMode,
    setConnectionMode,
    connectionSourceId,
    connectionSourcePosition,
    mousePosition,
    getAbsolutePosition,
    handleNodeClickForConnection,
    handleMouseMove,
    handlePaneClickForConnection,
  }
}
