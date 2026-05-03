import { useCallback, useState, useRef } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  ConnectionMode,
  useReactFlow,
  useViewport,
  type Connection,
  addEdge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowLeft, Save, Clock, Loader2, Pencil, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { DeleteDFDDialog } from '@/features/threat-models/components'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { useThreatModel, useDeleteDFD } from '@/features/threat-models/api/threat-models'
// DFD Editor internal imports
import { nodeTypes, edgeTypes } from './components'
import { DiagramToolbar } from './components/DiagramToolbar'
import { NodeEditPanel } from './components/panels/NodeEditPanel'
import { EdgeEditPanel } from './components/panels/EdgeEditPanel'
import { TrustBoundaryEdgeEditPanel } from './components/panels/TrustBoundaryEdgeEditPanel'
import { TemplateBrowser } from './components/TemplateBrowser'
import { CanvasOverlays } from './components/CanvasOverlays'
import { useDiagramState } from './hooks/useDiagramState'
import { useParentRelationships } from './hooks/useParentRelationships'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useConnectionMode } from './hooks/useConnectionMode'
import { useBoundaryMode } from './hooks/useBoundaryMode'
import { ThreatSummaryProvider } from './contexts/ThreatSummaryContext'
import type { DiagramNode, DiagramEdge, DataFlowEdge, TrustBoundaryEdge } from './types'

function DFDEditorContent() {
  const { diagramId, id: threatModelId } = useParams<{ id: string; diagramId: string }>()
  const navigate = useNavigate()
  const reactFlowWrapper = useRef<HTMLDivElement>(null)

  // State for UI
  const [selectedNode, setSelectedNode] = useState<DiagramNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<DiagramEdge | null>(null)
  const [showTemplates, setShowTemplates] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  // ReactFlow instance for coordinate conversion and edge queries
  const { screenToFlowPosition, getEdges } = useReactFlow()
  const { x: viewportX, y: viewportY, zoom } = useViewport()

  // Delete DFD mutation
  const deleteDFDMutation = useDeleteDFD()

  // Diagram state management
  const {
    diagram,
    nodes,
    edges,
    isLoading,
    isSaving,
    isError,
    setNodes,
    setEdges,
    onNodesChange,
    onEdgesChange,
    saveNow,
    updateTitle,
    undo,
    hasUnsavedChanges,
    lastSaved,
  } = useDiagramState({
    diagramId: diagramId || '',
    autoSaveInterval: 30000,
  })

  // State for editable title
  const [isEditingTitle, setIsEditingTitle] = useState(false)
  const [titleValue, setTitleValue] = useState('')
  const titleInputRef = useRef<HTMLInputElement>(null)

  // Fetch threat model for name display
  const { data: threatModel } = useThreatModel(threatModelId || '')

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

  // Mutual exclusion handlers for connection and boundary modes
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

  // Handle node click - delegates to mode hooks then falls through to selection
  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: DiagramNode) => {
      // Try boundary mode first
      const boundaryResult = handleNodeClickForBoundary(node)
      if (boundaryResult.consumed) {
        if (boundaryResult.selectedEdge) {
          setSelectedEdge(boundaryResult.selectedEdge)
          setSelectedNode(null)
        }
        return
      }

      // Try connection mode
      if (handleNodeClickForConnection(node)) return

      // Normal mode: select node for editing
      setSelectedNode(node)
      setSelectedEdge(null)
    },
    [handleNodeClickForBoundary, handleNodeClickForConnection]
  )

  // Handle edge selection
  const handleEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: DiagramEdge) => {
      setSelectedEdge(edge)
      setSelectedNode(null)
    },
    []
  )

  // Handle pane click (deselect)
  const handlePaneClick = useCallback(() => {
    setSelectedNode(null)
    setSelectedEdge(null)
    handlePaneClickForConnection()
    // Boundary source is NOT cleared here — React Flow fires onPaneClick
    // alongside onNodeClick for container nodes (trust zones)
  }, [handlePaneClickForConnection])

  // Handle node drag end - update parent relationships
  const handleNodeDragStop = useCallback(
    () => {
      requestAnimationFrame(() => {
        updateParentRelationships(nodes, setNodes)
      })
    },
    [nodes, setNodes, updateParentRelationships]
  )

  // Handle new connections
  const handleConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return

      // Block data flow connections between trust zones
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

  // Handle template insertion
  const handleInsertTemplate = useCallback(
    (templateNodes: DiagramNode[], templateEdges: DiagramEdge[]) => {
      const timestamp = Date.now()

      // Create ID mapping
      const idMap = new Map<string, string>()
      templateNodes.forEach((node, index) => {
        idMap.set(node.id, `${node.type}-${timestamp}-${index}`)
      })

      // Offset only root nodes to avoid overlap
      const offset = { x: 100, y: 100 }

      const newNodes: DiagramNode[] = templateNodes.map((node) => {
        const hasParent = node.parentId && idMap.has(node.parentId)
        return {
          ...node,
          id: idMap.get(node.id)!,
          position: hasParent
            ? node.position
            : {
                x: node.position.x + offset.x,
                y: node.position.y + offset.y,
              },
          parentId: hasParent ? idMap.get(node.parentId!) : undefined,
        }
      })

      const newEdges: DiagramEdge[] = templateEdges.map((edge, index) => ({
        ...edge,
        id: `edge-${timestamp}-${index}`,
        source: idMap.get(edge.source) || edge.source,
        target: idMap.get(edge.target) || edge.target,
      }))

      setNodes((nds) => [...nds, ...newNodes])
      setEdges((eds) => [...eds, ...newEdges])
      setShowTemplates(false)
    },
    [setNodes, setEdges]
  )

  // Keep selectedNode/selectedEdge in sync with actual node/edge data
  const currentSelectedNode = selectedNode
    ? (nodes.find((n) => n.id === selectedNode.id) as DiagramNode | undefined)
    : null

  const currentSelectedEdge = selectedEdge
    ? (edges.find((e) => e.id === selectedEdge.id) as DiagramEdge | undefined)
    : null

  // Handle deselect (also cancels boundary mode)
  const handleDeselect = useCallback(() => {
    setSelectedNode(null)
    setSelectedEdge(null)
    if (boundaryMode) {
      cancelBoundaryMode()
    }
  }, [boundaryMode, cancelBoundaryMode])

  const handleSave = useCallback(async () => {
    await saveNow()
  }, [saveNow])

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onSave: handleSave,
    onUndo: undo,
    onDeselect: handleDeselect,
    enabled: true,
  })

  // Format last saved time
  const formatLastSaved = (date: Date | null) => {
    if (!date) return 'Never saved'
    const now = new Date()
    const diff = Math.floor((now.getTime() - date.getTime()) / 1000)
    if (diff < 60) return 'Saved just now'
    if (diff < 3600) return `Saved ${Math.floor(diff / 60)}m ago`
    return `Saved ${Math.floor(diff / 3600)}h ago`
  }

  // Handle title editing
  const diagramTitle = diagram?.name || ''

  const handleTitleClick = useCallback(() => {
    if (diagram) {
      setTitleValue(diagramTitle)
      setIsEditingTitle(true)
      setTimeout(() => titleInputRef.current?.select(), 0)
    }
  }, [diagram, diagramTitle])

  const handleTitleSave = useCallback(async () => {
    const trimmedTitle = titleValue.trim()
    if (trimmedTitle && trimmedTitle !== diagramTitle) {
      await updateTitle(trimmedTitle)
    }
    setIsEditingTitle(false)
  }, [titleValue, diagramTitle, updateTitle])

  const handleTitleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        handleTitleSave()
      } else if (e.key === 'Escape') {
        setIsEditingTitle(false)
      }
    },
    [handleTitleSave]
  )

  // Handle DFD deletion
  const handleConfirmDelete = useCallback(
    (deleteOrphanedComponents: boolean) => {
      if (diagramId) {
        deleteDFDMutation.mutate(
          { dfdId: diagramId, deleteOrphanedComponents },
          {
            onSuccess: () => {
              setShowDeleteDialog(false)
              navigate(`/threat-models/${threatModelId}`)
            },
          }
        )
      }
    },
    [diagramId, deleteDFDMutation, navigate, threatModelId]
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-44px)]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (isError || !diagram) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-44px)] gap-4">
        <p className="text-muted-foreground">Failed to load diagram</p>
        <Button onClick={() => navigate(-1)}>Go Back</Button>
      </div>
    )
  }

  return (
    <ThreatSummaryProvider threatModelId={threatModelId}>
    <div className="flex flex-col h-[calc(100vh-44px)]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b bg-background">
        <div className="flex items-center gap-4">
          <Link
            to={`/threat-models/${threatModelId}`}
            className="flex items-center gap-2 text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm">Back</span>
          </Link>
          <div>
            {isEditingTitle ? (
              <input
                ref={titleInputRef}
                type="text"
                value={titleValue}
                onChange={(e) => setTitleValue(e.target.value)}
                onBlur={handleTitleSave}
                onKeyDown={handleTitleKeyDown}
                className="font-semibold bg-transparent border-b-2 border-primary outline-none px-0 py-0 min-w-[200px]"
                autoFocus
              />
            ) : (
              <button
                onClick={handleTitleClick}
                className="flex items-center gap-2 group text-left"
              >
                <h1 className="font-semibold">{diagramTitle}</h1>
                <Pencil className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
              </button>
            )}
            <p className="text-xs text-muted-foreground">
              {threatModel?.name ? `${threatModel.name}` : 'Data Flow Diagram'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Save status */}
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1 text-sm text-muted-foreground">
                  {isSaving ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : hasUnsavedChanges ? (
                    <div className="h-2 w-2 rounded-full bg-yellow-500" />
                  ) : (
                    <Clock className="h-4 w-4" />
                  )}
                  <span className="hidden sm:inline">
                    {isSaving
                      ? 'Saving...'
                      : hasUnsavedChanges
                      ? 'Unsaved changes'
                      : formatLastSaved(lastSaved)}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {hasUnsavedChanges
                  ? 'You have unsaved changes. Press Cmd/Ctrl+S to save.'
                  : `Last saved: ${lastSaved?.toLocaleString() || 'Never'}`}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <Button
            size="sm"
            onClick={handleSave}
            disabled={isSaving || !hasUnsavedChanges}
          >
            <Save className="h-4 w-4 mr-2" />
            Save
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setShowDeleteDialog(true)}
            className="text-red-600 hover:text-red-700 hover:bg-red-50"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      {/* Toolbar */}
      <DiagramToolbar
        connectionMode={connectionMode}
        onConnectionModeChange={handleConnectionModeChange}
        boundaryMode={boundaryMode}
        onBoundaryModeChange={handleBoundaryModeChange}
        onOpenTemplates={() => setShowTemplates(true)}
        onOpenThreatAnalysis={async () => {
          if (hasUnsavedChanges) {
            await handleSave()
          }
          navigate(`/threat-models/${threatModelId}`)
        }}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Canvas */}
        <div className="flex-1" ref={reactFlowWrapper} onMouseMove={handleMouseMove}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={handleConnect}
            onNodeClick={handleNodeClick}
            onEdgeClick={handleEdgeClick}
            onPaneClick={handlePaneClick}
            onNodeDragStop={handleNodeDragStop}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            connectionMode={ConnectionMode.Loose}
            defaultEdgeOptions={{
              type: 'dataFlow',
              animated: true,
            }}
            fitView
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
        </div>

        {/* Edit Panel */}
        {currentSelectedNode && (
          <NodeEditPanel
            node={currentSelectedNode}
            onClose={() => setSelectedNode(null)}
            threatModelId={threatModelId}
          />
        )}
        {currentSelectedEdge?.type === 'dataFlow' && (
          <EdgeEditPanel
            edge={currentSelectedEdge as DataFlowEdge}
            onClose={() => setSelectedEdge(null)}
            threatModelId={threatModelId}
          />
        )}
        {currentSelectedEdge?.type === 'trustBoundary' && (
          <TrustBoundaryEdgeEditPanel
            edge={currentSelectedEdge as TrustBoundaryEdge}
            onClose={() => setSelectedEdge(null)}
          />
        )}
      </div>

      {/* Template Browser Dialog */}
      {showTemplates && (
        <TemplateBrowser
          open={showTemplates}
          onOpenChange={setShowTemplates}
          onInsert={handleInsertTemplate}
        />
      )}

      {/* Delete DFD Dialog */}
      <DeleteDFDDialog
        dfdId={diagramId ?? null}
        dfdName={diagramTitle}
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        onConfirm={handleConfirmDelete}
        isDeleting={deleteDFDMutation.isPending}
      />
    </div>
    </ThreatSummaryProvider>
  )
}

export function DFDEditor() {
  return (
    <ReactFlowProvider>
      <DFDEditorContent />
    </ReactFlowProvider>
  )
}
