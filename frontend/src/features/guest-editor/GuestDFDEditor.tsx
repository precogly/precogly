import { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  ConnectionMode,
  useReactFlow,
  useViewport,
  type Connection,
  type XYPosition,
  addEdge,
  reconnectEdge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useOutletContext } from 'react-router-dom'
import { CanvasOverlays } from '@/features/dfd-editor/components/CanvasOverlays'
import { ExportImageDialog } from '@/features/dfd-editor/components/ExportImageDialog'
import { ComponentPanel } from '@/features/dfd-editor/components/panels/ComponentPanel'
import { GuestNodeEditPanel } from './components/GuestNodeEditPanel'
import { EdgeEditPanel } from '@/features/dfd-editor/components/panels/EdgeEditPanel'
import { TrustBoundaryEdgeEditPanel } from '@/features/dfd-editor/components/panels/TrustBoundaryEdgeEditPanel'
import { DFDNotationProvider } from '@/features/dfd-editor/context/DFDNotationContext'
import { useParentRelationships } from '@/features/dfd-editor/hooks/useParentRelationships'
import { useKeyboardShortcuts } from '@/features/dfd-editor/hooks/useKeyboardShortcuts'
import { useConnectionMode } from '@/features/dfd-editor/hooks/useConnectionMode'
import { useBoundaryMode } from '@/features/dfd-editor/hooks/useBoundaryMode'
import { exportDiagramImage, captureDiagramImage, type ExportImageOptions } from '@/features/dfd-editor/lib/export-diagram-image'
import type {
  DiagramNode,
  DiagramEdge,
  DataFlowEdge,
  TrustBoundaryEdge,
} from '@/features/dfd-editor/types'
import { useCreateNode, useHandleDrop } from '@/features/dfd-editor/hooks/useCreateNode'
import { NOTATION_NODE_SIZES } from '@/features/dfd-editor/types/notation'
import { GuestThreatSection } from './components/GuestThreatSection'
import { guestNodeTypes, guestEdgeTypes } from './components/GuestNodeWrapper'
import { useGuestEditor } from './context/GuestEditorContext'
import type { GuestDiagramOutletContext } from './GuestLayout'

function GuestDFDEditorContent() {
  const reactFlowWrapper = useRef<HTMLDivElement>(null)

  // Consume diagram state from layout via outlet context
  const {
    title,
    nodes,
    edges,
    setNodes,
    setEdges,
    onNodesChange,
    onEdgesChange,
    undo,
    redo,
    notationStyle,
    exportImageRef,
    captureImageRef,
    onCacheImage,
    showComponentPanel,
    setShowComponentPanel,
    exportDialogOpen,
    setExportDialogOpen,
  } = useOutletContext<GuestDiagramOutletContext>()

  // Resize nodes when notation style changes (triggered from header dropdown)
  const previousNotationRef = useRef(notationStyle)
  useEffect(() => {
    if (previousNotationRef.current === notationStyle) return
    previousNotationRef.current = notationStyle
    const newSizes = NOTATION_NODE_SIZES[notationStyle]

    setNodes((currentNodes) => {
      const containerProcessIds = new Set(
        currentNodes
          .filter((n) => n.parentId)
          .map((n) => n.parentId!)
          .filter((parentId) => currentNodes.find((n) => n.id === parentId)?.type === 'process')
      )

      return currentNodes.map((node) => {
        if (
          (node.type === 'process' && !containerProcessIds.has(node.id)) ||
          node.type === 'datastore'
        ) {
          const defaultSize = newSizes[node.type]
          if (defaultSize) {
            return {
              ...node,
              style: { ...node.style, width: defaultSize.width, height: defaultSize.height },
            }
          }
        }
        return node
      })
    })
  }, [notationStyle, setNodes])

  // State for UI
  const [selectedNode, setSelectedNode] = useState<DiagramNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<DiagramEdge | null>(null)

  // ReactFlow instance
  const { screenToFlowPosition, getNodes, getEdges, getViewport, setViewport, getNodesBounds } = useReactFlow()
  const { x: viewportX, y: viewportY, zoom } = useViewport()
  const guestEditor = useGuestEditor()

  // Parent relationship detection
  const { updateParentRelationships } = useParentRelationships()

  // Connection mode hook
  const {
    connectionMode,
    setConnectionMode,
    connectionSourceId,
    connectionSourcePosition,
    mousePosition,
    getAbsolutePosition,
    handleNodeClickForConnection,
    handleMouseMove,
    handlePaneClickForConnection,
  } = useConnectionMode({ nodes, edges, setEdges, screenToFlowPosition })

  // Boundary mode hook
  const {
    boundaryMode,
    setBoundaryMode,
    boundarySourceId,
    boundarySourceZoneInfo,
    handleNodeClickForBoundary,
    cancelBoundaryMode,
  } = useBoundaryMode({ nodes, setEdges, getEdges: getEdges as () => DiagramEdge[], getAbsolutePosition })

  // Mutual exclusion
  const handleConnectionModeChange = useCallback(
    (enabled: boolean) => {
      if (enabled) setBoundaryMode(false)
      setConnectionMode(enabled)
    },
    [setBoundaryMode, setConnectionMode]
  )

  const handleBoundaryModeChange = useCallback(
    (enabled: boolean) => {
      if (enabled) setConnectionMode(false)
      setBoundaryMode(enabled)
    },
    [setConnectionMode, setBoundaryMode]
  )

  const getCanvasCenterPosition = useCallback((): XYPosition => {
    const bounds = reactFlowWrapper.current?.getBoundingClientRect()
    return screenToFlowPosition({
      x: bounds ? bounds.left + bounds.width / 2 : window.innerWidth / 2,
      y: bounds ? bounds.top + bounds.height / 2 : window.innerHeight / 2,
    })
  }, [screenToFlowPosition])

  // Drag-and-drop from toolbar
  const { createNode } = useCreateNode(notationStyle)

  const { handleDragOver, handleDrop } = useHandleDrop({
    screenToFlowPosition,
    createNode,
    nodes,
    setNodes,
    updateParentRelationships,
    setSelectedNode,
  })

  // Register export image handler so the header can call it
  useEffect(() => {
    exportImageRef.current = (format: 'png' | 'svg', options?: ExportImageOptions) => {
      if (!reactFlowWrapper.current) return
      const filename = (title || 'diagram')
        .replace(/[^a-zA-Z0-9-_ ]/g, '')
        .replace(/\s+/g, '-')
        .toLowerCase()
      return exportDiagramImage(format, filename, reactFlowWrapper.current, nodes, getViewport, setViewport, getNodesBounds, options)
    }
    return () => { exportImageRef.current = null }
  }, [exportImageRef, title, nodes, getNodesBounds, getViewport, setViewport])

  // Register capture image handler so the header can capture PNG bytes for the Word report
  useEffect(() => {
    captureImageRef.current = async (): Promise<Uint8Array | null> => {
      if (!reactFlowWrapper.current || nodes.length === 0) return null
      return captureDiagramImage(reactFlowWrapper.current, nodes, getViewport, setViewport, getNodesBounds)
    }
    // Canvas re-mounted — invalidate cached image since user may edit the diagram
    onCacheImage(null)
    return () => { captureImageRef.current = null }
  }, [captureImageRef, nodes, getNodesBounds, getViewport, setViewport, onCacheImage])

  // Handle node click
  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: DiagramNode) => {
      const boundaryResult = handleNodeClickForBoundary(node)
      if (boundaryResult.consumed) {
        if (boundaryResult.selectedEdge) {
          setSelectedEdge(boundaryResult.selectedEdge)
          setSelectedNode(null)
        }
        return
      }
      if (handleNodeClickForConnection(node)) return
      setSelectedNode(node)
      setSelectedEdge(null)
    },
    [handleNodeClickForBoundary, handleNodeClickForConnection]
  )

  const handleEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: DiagramEdge) => {
      setSelectedEdge(edge)
      setSelectedNode(null)
    },
    []
  )

  const startEdgeEditing = useCallback((initialText: string) => {
    setEdges((currentEdges) => currentEdges.map((edge) =>
      edge.selected
        ? { ...edge, data: { ...edge.data, label: initialText, isInlineEditing: true } }
        : edge
    ))
  }, [setEdges])

  const handleEdgeDoubleClick = useCallback(
    (_event: React.MouseEvent, edge: DiagramEdge) => {
      if (edge.type !== 'dataFlow') return
      setEdges((currentEdges) => currentEdges.map((currentEdge) => {
        if (currentEdge.type !== 'dataFlow') return currentEdge
        return {
          ...currentEdge,
          data: { ...currentEdge.data, isInlineEditing: currentEdge.id === edge.id },
        }
      }))
    },
    [setEdges]
  )

  // Handle double-click on node to enable inline label editing
  const handleNodeDoubleClick = useCallback(
    (_event: React.MouseEvent, node: DiagramNode) => {
      setNodes((nds) =>
        nds.map((n) => ({
          ...n,
          data: { ...n.data, isInlineEditing: n.id === node.id },
        }))
      )
    },
    [setNodes]
  )

  const handlePaneClick = useCallback(() => {
    setSelectedNode(null)
    setSelectedEdge(null)
    handlePaneClickForConnection()
    // Clear any inline editing state
    setNodes((nds) =>
      nds.some((n) => n.data.isInlineEditing)
        ? nds.map((n) =>
            n.data.isInlineEditing ? { ...n, data: { ...n.data, isInlineEditing: false } } : n
          )
        : nds
    )
    setEdges((eds) =>
      eds.some((edge) => edge.data?.isInlineEditing)
        ? eds.map((edge) =>
            edge.data?.isInlineEditing ? { ...edge, data: { ...edge.data, isInlineEditing: false } } : edge
          )
        : eds
    )
  }, [handlePaneClickForConnection, setEdges, setNodes])

  const handleNodeDragStop = useCallback(() => {
    requestAnimationFrame(() => {
      updateParentRelationships(nodes, setNodes)
    })
  }, [nodes, setNodes, updateParentRelationships])

  const handleConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return
      const sourceNode = nodes.find((n) => n.id === connection.source)
      const targetNode = nodes.find((n) => n.id === connection.target)
      if (sourceNode?.type === 'trustZone' && targetNode?.type === 'trustZone') return

      const newEdge: DataFlowEdge = {
        id: `edge-${Date.now()}`,
        source: connection.source,
        target: connection.target,
        sourceHandle: connection.sourceHandle,
        targetHandle: connection.targetHandle,
        type: 'dataFlow',
        animated: true,
        data: {
          label: '',
          encrypted: false,
          authenticated: false,
        },
      }
      setEdges((eds) => addEdge(newEdge, eds) as DiagramEdge[])
    },
    [nodes, setEdges]
  )

  const handleReconnect = useCallback(
    (oldEdge: DiagramEdge, connection: Connection) => {
      setEdges((currentEdges) => reconnectEdge(oldEdge, connection, currentEdges) as DiagramEdge[])
    },
    [setEdges]
  )

  // Sync selected node/edge with current data
  const currentSelectedNode = selectedNode
    ? (nodes.find((n) => n.id === selectedNode.id) as DiagramNode | undefined)
    : null

  const currentSelectedEdge = selectedEdge
    ? (edges.find((e) => e.id === selectedEdge.id) as DiagramEdge | undefined)
    : null

  const handleDeselect = useCallback(() => {
    setSelectedNode(null)
    setSelectedEdge(null)
    if (boundaryMode) {
      cancelBoundaryMode()
    }
  }, [boundaryMode, cancelBoundaryMode])

  // Keep keyboard deletion in sync with the guest threat state. React Flow
  // only removes canvas items, while threats and countermeasures are held in
  // separate guest-editor stores and are included in exports.
  const handleDelete = useCallback(() => {
    const currentNodes = getNodes() as DiagramNode[]
    const currentEdges = getEdges() as DiagramEdge[]
    const selectedNodes = currentNodes.filter((node) => node.selected)
    const selectedEdges = currentEdges.filter((edge) => edge.selected)

    if (selectedNodes.length === 0 && selectedEdges.length === 0) return

    const selectedNodeIds = new Set(selectedNodes.map((node) => node.id))
    const deletedTargetIds = new Set([
      ...selectedNodeIds,
      ...selectedEdges.map((edge) => edge.id),
      ...currentEdges
        .filter((edge) => selectedNodeIds.has(edge.source) || selectedNodeIds.has(edge.target))
        .map((edge) => edge.id),
    ])

    if (guestEditor) {
      for (const targetId of deletedTargetIds) {
        for (const threat of guestEditor.getThreatsForTarget(targetId)) {
          guestEditor.removeThreat(threat.id)
        }
      }
    }

    const boundaryIds = selectedNodes
      .filter((node) => node.type === 'trustZone' || node.type === 'systemScope')
      .map((node) => node.id)

    const updatedNodes = currentNodes
      .filter((node) => !selectedNodeIds.has(node.id))
      .map((node) => {
        if (node.parentId && boundaryIds.includes(node.parentId)) {
          const parent = currentNodes.find((candidate) => candidate.id === node.parentId)
          if (parent) {
            return {
              ...node,
              parentId: undefined,
              position: {
                x: node.position.x + parent.position.x,
                y: node.position.y + parent.position.y,
              },
            }
          }
        }
        return node
      })

    const updatedEdges = currentEdges.filter(
      (edge) =>
        !selectedEdges.some((selectedEdge) => selectedEdge.id === edge.id) &&
        !selectedNodeIds.has(edge.source) &&
        !selectedNodeIds.has(edge.target)
    )

    setNodes(updatedNodes)
    setEdges(updatedEdges)
  }, [getEdges, getNodes, guestEditor, setEdges, setNodes])
  const startNodeEditing = useCallback((initialText: string) => {
    setNodes((currentNodes) => currentNodes.map((node) =>
      node.selected
        ? { ...node, data: { ...node.data, label: initialText, isInlineEditing: true } }
        : node
    ))
  }, [setNodes])

  const pasteNodeLabel = useCallback((text: string) => {
    setNodes((currentNodes) => currentNodes.map((node) =>
      node.selected
        ? { ...node, data: { ...node.data, label: text, isInlineEditing: true } }
        : node
    ))
  }, [setNodes])

  // Keyboard shortcuts (save is a no-op in guest — handled by header download)
  useKeyboardShortcuts({
    onUndo: undo,
    onRedo: redo,
    onDeselect: handleDeselect,
    onDelete: handleDelete,
    onStartEdgeEditing: startEdgeEditing,
    onStartNodeEditing: startNodeEditing,
    onPasteText: pasteNodeLabel,
    enabled: true,
  })

  const fitViewOptions = useMemo(() => ({ maxZoom: 0.75 }), [])

  // Determine guest threat target type for the selected node
  const getNodeTargetType = (node: DiagramNode): 'component' | 'systemScope' => {
    if (node.type === 'systemScope') return 'systemScope'
    return 'component'
  }

  return (
    <>
    <div className="flex flex-1 overflow-hidden">
      {/* Component Panel (sidebar) */}
      {showComponentPanel && (
        <ComponentPanel
          onClose={() => setShowComponentPanel(false)}
          connectionMode={connectionMode}
          onConnectionModeChange={handleConnectionModeChange}
          boundaryMode={boundaryMode}
          onBoundaryModeChange={handleBoundaryModeChange}
          getCanvasCenterPosition={getCanvasCenterPosition}
          notationStyle={notationStyle}
        />
      )}
      {/* Canvas */}
      <div className={`flex-1 ${connectionMode ? 'connection-mode' : ''}`} ref={reactFlowWrapper} onMouseMove={handleMouseMove} onDragOver={handleDragOver} onDrop={handleDrop}>
          <DFDNotationProvider notationStyle={notationStyle}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={handleConnect}
              onReconnect={handleReconnect}
              edgesReconnectable
              onNodeClick={handleNodeClick}
              onNodeDoubleClick={handleNodeDoubleClick}
              onEdgeClick={handleEdgeClick}
              onEdgeDoubleClick={handleEdgeDoubleClick}
              onPaneClick={handlePaneClick}
              onNodeDragStop={handleNodeDragStop}
              nodeTypes={guestNodeTypes}
              edgeTypes={guestEdgeTypes}
              connectionMode={ConnectionMode.Loose}
              defaultEdgeOptions={{
                type: 'dataFlow',
                animated: true,
              }}
              fitView
              fitViewOptions={fitViewOptions}
              selectionOnDrag
              panOnDrag={[1, 2]}
              panOnScroll
              snapToGrid
              snapGrid={[15, 15]}
              minZoom={0.1}
              maxZoom={4}
              deleteKeyCode={null}
            >
              <CanvasOverlays
                viewportX={viewportX}
                viewportY={viewportY}
                zoom={zoom}
                connectionMode={connectionMode}
                connectionSourceId={connectionSourceId}
                connectionSourcePosition={connectionSourcePosition}
                mousePosition={mousePosition}
                boundaryMode={boundaryMode}
                boundarySourceId={boundarySourceId}
                boundarySourceZoneInfo={boundarySourceZoneInfo}
              />
              <Background gap={15} size={1} />
              <Controls />
            </ReactFlow>
          </DFDNotationProvider>
        </div>

        {/* Edit Panels */}
        {currentSelectedNode && (
          <GuestNodeEditPanel
            node={currentSelectedNode}
            onClose={() => setSelectedNode(null)}
            renderExtra={
              currentSelectedNode.type !== 'trustZone' && currentSelectedNode.type !== 'stickyNote' ? (
                <GuestThreatSection
                  targetId={currentSelectedNode.id}
                  targetType={getNodeTargetType(currentSelectedNode)}
                  targetName={currentSelectedNode.data.label || currentSelectedNode.type || 'Node'}
                />
              ) : undefined
            }
          />
        )}
        {currentSelectedEdge?.type === 'dataFlow' && (
          <EdgeEditPanel
            edge={currentSelectedEdge as DataFlowEdge}
            onClose={() => setSelectedEdge(null)}
            renderExtra={
              <GuestThreatSection
                targetId={currentSelectedEdge.id}
                targetType="dataflow"
                targetName={currentSelectedEdge.data?.label || 'Data Flow'}
              />
            }
          />
        )}
        {currentSelectedEdge?.type === 'trustBoundary' && (
          <TrustBoundaryEdgeEditPanel
            edge={currentSelectedEdge as TrustBoundaryEdge}
            onClose={() => setSelectedEdge(null)}
          />
        )}
      </div>
      <ExportImageDialog
        open={exportDialogOpen}
        onOpenChange={setExportDialogOpen}
        onExport={(format, options) => exportImageRef.current?.(format, options)}
      />
    </>
  )
}

export function GuestDFDEditorPage() {
  return (
    <ReactFlowProvider>
      <GuestDFDEditorContent />
    </ReactFlowProvider>
  )
}
