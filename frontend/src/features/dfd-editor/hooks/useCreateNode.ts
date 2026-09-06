import { useCallback } from 'react'
import { useReactFlow, type XYPosition } from '@xyflow/react'
import type { DiagramNode, DiagramNodeType } from '../types'
import { type DFDNotationStyle, NOTATION_NODE_SIZES, TECHNOLOGY_NODE_SIZES } from '../types/notation'

const defaultData: Record<DiagramNodeType, Record<string, unknown>> = {
  humanActor: { label: 'New Human Actor', technology: '' },
  systemActor: { label: 'New System Actor', technology: '' },
  process: { label: 'New Process', technology: '' },
  datastore: { label: 'New Data Store', technology: '' },
  trustZone: { label: 'Trust Zone', trustLevel: 25, zoneColor: '#ef4444' },
  systemScope: { label: 'System Scope' },
  stickyNote: { label: 'Add a note', noteColor: 'yellow', textSize: 'medium', bold: false, italic: false },
}

export function useCreateNode(notationStyle: DFDNotationStyle) {
  const { addNodes, setNodes } = useReactFlow()
  const nodeSizes = NOTATION_NODE_SIZES[notationStyle]

  const createNode = useCallback(
    (type: DiagramNodeType, dropPosition: XYPosition, options?: { technology?: string; label?: string }) => {
      const nodeSize = (options?.technology && TECHNOLOGY_NODE_SIZES[type]) || nodeSizes[type] || { width: 120, height: 70 }

      const position = {
        x: dropPosition.x - nodeSize.width / 2,
        y: dropPosition.y - nodeSize.height / 2,
      }

      const id = `${type}-${Date.now()}`

      const data: Record<string, unknown> = { ...defaultData[type], isNewlyInserted: true }
      if (options?.label) data.label = options.label
      if (options?.technology && 'technology' in data) data.technology = options.technology

      addNodes({
        id,
        type,
        position,
        data,
        style: { width: nodeSize.width, height: nodeSize.height },
      })

      setTimeout(() => {
        setNodes((currentNodes) =>
          currentNodes.map((n) =>
            n.id === id ? { ...n, data: { ...n.data, isNewlyInserted: false } } : n
          )
        )
      }, 2000)

      return id
    },
    [addNodes, setNodes, nodeSizes]
  )

  return { createNode }
}

/**
 * Shared drop handler for both signed-in and guest DFD editors.
 * Creates the node, resolves parent relationships, then selects the node
 * and enters inline editing mode so the user can start typing immediately.
 */
export function useHandleDrop({
  screenToFlowPosition,
  createNode,
  nodes,
  setNodes,
  updateParentRelationships,
  setSelectedNode,
}: {
  screenToFlowPosition: (position: { x: number; y: number }) => XYPosition
  createNode: (type: DiagramNodeType, dropPosition: XYPosition, options?: { technology?: string; label?: string }) => string
  nodes: DiagramNode[]
  setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>>
  updateParentRelationships: (nodes: DiagramNode[], setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>>) => void
  setSelectedNode: (node: DiagramNode | null) => void
}) {
  const handleDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault()
      const nodeType = event.dataTransfer.getData('application/reactflow-node-type') as DiagramNodeType
      if (!nodeType) return
      const componentRef = event.dataTransfer.getData('application/reactflow-component-ref')
      const componentName = event.dataTransfer.getData('application/reactflow-component-name')
      const dropPosition = screenToFlowPosition({ x: event.clientX, y: event.clientY })
      const options = componentRef ? { technology: componentRef, label: componentName || undefined } : undefined
      const newNodeId = createNode(nodeType, dropPosition, options)
      // Let ReactFlow render the new node, then check parent relationships
      requestAnimationFrame(() => {
        updateParentRelationships(nodes, setNodes)
      })
      // After the node is fully rendered and parent relationships resolved,
      // select it and enter inline editing mode so the user can start typing immediately
      setTimeout(() => {
        setNodes((currentNodes) => {
          const newNode = currentNodes.find((n) => n.id === newNodeId)
          if (newNode) setSelectedNode(newNode)
          return currentNodes.map((n) =>
            n.id === newNodeId
              ? { ...n, data: { ...n.data, isInlineEditing: true } }
              : n
          )
        })
      }, 100)
    },
    [screenToFlowPosition, createNode, nodes, setNodes, updateParentRelationships, setSelectedNode]
  )

  return { handleDragOver, handleDrop }
}
