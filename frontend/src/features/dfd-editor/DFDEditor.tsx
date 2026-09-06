import { useCallback, useMemo, useState, useRef, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
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
import { Save, Clock, Loader2, Pencil, Trash2, ShieldAlert, Info, Undo2, Redo2, HelpCircle, LayoutTemplate, ImageDown, PanelLeft, MoreHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { DeleteDFDDialog } from '@/features/threat-models/components'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useThreatModel, useDeleteDFD } from '@/features/threat-models/api/threat-models'
import { OwlMark } from '@/features/ai/components/OwlMark'
import { AI_PROVIDER_SETTINGS_PATH } from '@/features/ai/constants'
// DFD Editor internal imports
import { canvasNodeTypes, canvasEdgeTypes } from './components/nodes/CanvasNodeWrapper'
import { NodeEditPanel } from './components/panels/NodeEditPanel'
import { EdgeEditPanel } from './components/panels/EdgeEditPanel'
import { CanvasThreatSection } from './components/panels/CanvasThreatSection'
import { useThreatModelThreats } from '@/features/threat-models/api/threats'
import { TrustBoundaryEdgeEditPanel } from './components/panels/TrustBoundaryEdgeEditPanel'
import { ComponentPanel } from './components/panels/ComponentPanel'
import { TemplateBrowser } from './components/TemplateBrowser'
import { GenerateDFDDialog } from './components/GenerateDFDDialog'
import { useDfdAiAvailability } from './api/generate-dfd'
import { ExportImageDialog } from './components/ExportImageDialog'
import { CanvasOverlays } from './components/CanvasOverlays'
import { DFDNotationProvider } from './context/DFDNotationContext'
import { useDiagramState } from './hooks/useDiagramState'
import { useParentRelationships } from './hooks/useParentRelationships'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useConnectionMode } from './hooks/useConnectionMode'
import { useBoundaryMode } from './hooks/useBoundaryMode'
import type { DiagramNode, DiagramEdge, DataFlowEdge, TrustBoundaryEdge } from './types'
import { useCreateNode, useHandleDrop } from './hooks/useCreateNode'
import { type DFDNotationStyle, NOTATION_NODE_SIZES } from './types/notation'
import { exportDiagramImage, type ExportImageOptions } from './lib/export-diagram-image'

function DFDEditorContent() {
  const { diagramId, id: threatModelId } = useParams<{ id: string; diagramId: string }>()
  const navigate = useNavigate()
  const reactFlowWrapper = useRef<HTMLDivElement>(null)

  // State for UI
  const [selectedNode, setSelectedNode] = useState<DiagramNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<DiagramEdge | null>(null)
  const [showTemplates, setShowTemplates] = useState(false)
  const [showGenerateDFD, setShowGenerateDFD] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [showComponentPanel, setShowComponentPanel] = useState(true)
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  // ReactFlow instance for coordinate conversion and edge queries
  const { screenToFlowPosition, getEdges, getViewport, setViewport, getNodesBounds } = useReactFlow()
  const { x: viewportX, y: viewportY, zoom } = useViewport()

  // Delete DFD mutation
  const deleteDFDMutation = useDeleteDFD()

  // Diagram state management
  const {
    diagram,
    nodes,
    edges,
    initialNotationStyle,
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
    redo,
    canUndo,
    canRedo,
    hasUnsavedChanges,
    lastSaved,
  } = useDiagramState({
    diagramId: diagramId || '',
    autoSaveInterval: 30000,
  })

  // Notation style state
  const [notationStyle, setNotationStyle] = useState<DFDNotationStyle>('yourdon')

  // Sync notationStyle from loaded diagram data
  useEffect(() => {
    setNotationStyle(initialNotationStyle)
  }, [initialNotationStyle])

  // Handle notation change — resize affected nodes to new notation defaults
  const handleNotationChange = useCallback(
    (newNotation: DFDNotationStyle) => {
      setNotationStyle(newNotation)
      const newSizes = NOTATION_NODE_SIZES[newNotation]

      setNodes((currentNodes) => {
        // Determine which process nodes are containers (have children)
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
    },
    [setNodes]
  )

  // State for editable title
  const [isEditingTitle, setIsEditingTitle] = useState(false)
  const [titleValue, setTitleValue] = useState('')
  const titleInputRef = useRef<HTMLInputElement>(null)

  // Fetch threat model for name display
  const { data: threatModel } = useThreatModel(threatModelId || '')

  // Fetch threat data for canvas badges and threat sections
  const { data: threatData } = useThreatModelThreats(threatModelId)

  // AI availability for Generate DFD button
  const { data: aiAvailability } = useDfdAiAvailability(threatModelId)
  const aiAvailable = aiAvailability?.available ?? false

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

  // Handle pane click (deselect)
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
    // Boundary source is NOT cleared here — React Flow fires onPaneClick
    // alongside onNodeClick for container nodes (trust zones)
  }, [handlePaneClickForConnection, setEdges, setNodes])

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

  const handleReconnect = useCallback(
    (oldEdge: DiagramEdge, connection: Connection) => {
      setEdges((currentEdges) => reconnectEdge(oldEdge, connection, currentEdges) as DiagramEdge[])
    },
    [setEdges]
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

  // Wrap saveNow for keyboard shortcut to pass notation style
  const handleKeyboardSave = useCallback(async () => {
    await saveNow(notationStyle)
  }, [saveNow, notationStyle])

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onSave: handleKeyboardSave,
    onUndo: undo,
    onRedo: redo,
    onDeselect: handleDeselect,
    onStartEdgeEditing: startEdgeEditing,
    onStartNodeEditing: startNodeEditing,
    onPasteText: pasteNodeLabel,
    enabled: true,
  })

  const fitViewOptions = useMemo(() => ({ maxZoom: 0.75 }), [])

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

  // Export diagram as image
  const handleExportImage = useCallback(
    (format: 'png' | 'svg', options?: ExportImageOptions) => {
      if (!reactFlowWrapper.current) return
      const filename = (diagramTitle || 'diagram')
        .replace(/[^a-zA-Z0-9-_ ]/g, '')
        .replace(/\s+/g, '-')
        .toLowerCase()
      return exportDiagramImage(format, filename, reactFlowWrapper.current, nodes, getViewport, setViewport, getNodesBounds, options)
    },
    [diagramTitle, getNodesBounds, getViewport, nodes, setViewport]
  )

  // Keyboard shortcut help (? key)
  useEffect(() => {
    const handleShortcutHelp = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return
      if (event.key === '?') {
        event.preventDefault()
        setShortcutsOpen(true)
      }
    }
    window.addEventListener('keydown', handleShortcutHelp)
    return () => window.removeEventListener('keydown', handleShortcutHelp)
  }, [])

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
    <div className="flex flex-col h-[calc(100vh-44px)]">
      {/* Merged header (diagram header + toolbar items) */}
      <TooltipProvider delayDuration={300}>
        <div className="flex items-center gap-2 px-4 py-2 border-b bg-background min-h-[48px]">
          {/* Sidebar toggle */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className={cn('gap-1', showComponentPanel && 'bg-muted')}
                onClick={() => setShowComponentPanel((prev) => !prev)}
              >
                <PanelLeft className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">
              {showComponentPanel ? 'Hide' : 'Show'} component panel
            </TooltipContent>
          </Tooltip>

          <div className="mr-2 min-w-0 max-w-[240px] shrink">
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
                <h1 className="font-semibold truncate">{diagramTitle}</h1>
                <Pencil className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
              </button>
            )}
            <p className="text-xs text-muted-foreground truncate">
              {threatModel?.name ? `${threatModel.name}` : 'Data Flow Diagram'}
            </p>
          </div>

          {/* Canvas tools (from toolbar) */}
          <div className="hidden xl:flex items-center gap-0.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={undo} disabled={!canUndo} aria-label="Undo">
                  <Undo2 className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Undo (Ctrl/Cmd + Z)</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={redo} disabled={!canRedo} aria-label="Redo">
                  <Redo2 className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Redo (Ctrl/Cmd + Shift + Z)</TooltipContent>
            </Tooltip>
          </div>

          <div className="hidden xl:block">
            <Select
              value={notationStyle}
              onValueChange={(value) => handleNotationChange(value as DFDNotationStyle)}
            >
              <SelectTrigger className="h-8 w-[140px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="dfd3">DFD3</SelectItem>
                <SelectItem value="yourdon">Yourdon</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="hidden xl:block">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label="Keyboard shortcuts"
                  onClick={() => setShortcutsOpen(true)}
                >
                  <HelpCircle className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Keyboard shortcuts (?)</TooltipContent>
            </Tooltip>
          </div>

          <Separator orientation="vertical" className="hidden xl:block h-6" />

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                onClick={() => setShowTemplates(true)}
              >
                <LayoutTemplate className="h-4 w-4" />
                <span className="hidden xl:inline">Templates</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Browse and insert pre-built diagram templates</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn('gap-2', !aiAvailable && 'text-muted-foreground')}
                onClick={aiAvailable ? () => setShowGenerateDFD(true) : () => navigate(AI_PROVIDER_SETTINGS_PATH)}
              >
                <OwlMark className="h-4 w-4" />
                <span className="hidden xl:inline">Generate</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">
              {aiAvailable ? 'Generate DFD with AI' : 'Set up an AI provider to use this'}
            </TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="gap-2"
                onClick={() => setExportDialogOpen(true)}
              >
                <ImageDown className="h-4 w-4" />
                <span className="hidden xl:inline">Export Image</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Download diagram as PNG or SVG</TooltipContent>
          </Tooltip>

          {/* Overflow menu for narrow viewports */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="xl:hidden h-8 w-8" aria-label="More options">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={undo} disabled={!canUndo}>
                <Undo2 className="h-4 w-4 mr-2" />
                Undo
                <DropdownMenuShortcut>⌘Z</DropdownMenuShortcut>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={redo} disabled={!canRedo}>
                <Redo2 className="h-4 w-4 mr-2" />
                Redo
                <DropdownMenuShortcut>⇧⌘Z</DropdownMenuShortcut>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuLabel className="text-xs text-muted-foreground">Notation</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={notationStyle} onValueChange={(value) => handleNotationChange(value as DFDNotationStyle)}>
                <DropdownMenuRadioItem value="dfd3">DFD3</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="yourdon">Yourdon</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setShortcutsOpen(true)}>
                <HelpCircle className="h-4 w-4 mr-2" />
                Keyboard shortcuts
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => setShowDeleteDialog(true)}
                className="text-red-600 focus:text-red-600"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete diagram
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Right-aligned items */}
          <div className="flex items-center gap-2 ml-auto shrink-0">
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
                  <span className="hidden xl:inline">
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

            <Button
              size="sm"
              variant="outline"
              onClick={() => saveNow(notationStyle)}
              disabled={isSaving || !hasUnsavedChanges}
            >
              <Save className="h-4 w-4 mr-2" />
              Save
            </Button>

            <Button
              size="sm"
              onClick={async () => {
                if (hasUnsavedChanges) {
                  await saveNow(notationStyle)
                }
                navigate(`/threat-models/${threatModelId}`)
              }}
            >
              <ShieldAlert className="h-4 w-4 mr-2" />
              Analyze Threats
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowDeleteDialog(true)}
              className="hidden xl:inline-flex text-red-600 hover:text-red-700 hover:bg-red-50"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete
            </Button>
          </div>
        </div>
      </TooltipProvider>

      {/* Reference diagram banner */}
      {diagram && !diagram.isPrimary && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-amber-50 border-b border-amber-200 text-amber-800 text-sm">
          <Info className="h-4 w-4 shrink-0" />
          <span>
            This is a reference diagram. Components here are not synced to threat analysis.
          </span>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        {/* Component Panel */}
        {showComponentPanel && (
          <ComponentPanel
            threatModelId={threatModelId}
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
              nodeTypes={canvasNodeTypes}
              edgeTypes={canvasEdgeTypes}
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

        {/* Edit Panel */}
        {currentSelectedNode && (
          <NodeEditPanel
            node={currentSelectedNode}
            onClose={() => setSelectedNode(null)}
            threatModelId={threatModelId}
            renderExtra={
              currentSelectedNode.type !== 'trustZone' && currentSelectedNode.type !== 'stickyNote' ? (
                <CanvasThreatSection
                  threatModelId={threatModelId}
                  canvasId={currentSelectedNode.id}
                  targetType="component"
                  targetName={currentSelectedNode.data.label || currentSelectedNode.type || 'Node'}
                  backendId={
                    (currentSelectedNode.data as { componentId?: number }).componentId ??
                    threatData?.nodeComponentMap[currentSelectedNode.id]?.componentId
                  }
                />
              ) : undefined
            }
          />
        )}
        {currentSelectedEdge?.type === 'dataFlow' && (
          <EdgeEditPanel
            edge={currentSelectedEdge as DataFlowEdge}
            onClose={() => setSelectedEdge(null)}
            threatModelId={threatModelId}
            renderExtra={
              <CanvasThreatSection
                threatModelId={threatModelId}
                canvasId={currentSelectedEdge.id}
                targetType="dataflow"
                targetName={(currentSelectedEdge as DataFlowEdge).data?.label || 'Data Flow'}
                backendId={
                  (currentSelectedEdge as DataFlowEdge).data?.dataflowId ??
                  threatData?.edgeDataflowMap[currentSelectedEdge.id]?.dataflowId
                }
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

      {/* Template Browser Dialog */}
      {showTemplates && (
        <TemplateBrowser
          open={showTemplates}
          onOpenChange={setShowTemplates}
          onInsert={handleInsertTemplate}
          threatModelId={threatModelId}
        />
      )}

      {/* Generate DFD Dialog */}
      <GenerateDFDDialog
        open={showGenerateDFD}
        onOpenChange={setShowGenerateDFD}
        threatModelId={threatModelId}
        onInsert={handleInsertTemplate}
      />

      {/* Delete DFD Dialog */}
      <DeleteDFDDialog
        dfdId={diagramId ?? null}
        dfdName={diagramTitle}
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        onConfirm={handleConfirmDelete}
        isDeleting={deleteDFDMutation.isPending}
      />

      {/* Export Image Dialog */}
      <ExportImageDialog
        open={exportDialogOpen}
        onOpenChange={setExportDialogOpen}
        onExport={handleExportImage}
      />

      {/* Keyboard Shortcuts Dialog */}
      <Dialog open={shortcutsOpen} onOpenChange={setShortcutsOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Keyboard shortcuts</DialogTitle>
            <DialogDescription>Shortcuts are active when the canvas is focused and a form field is not being edited.</DialogDescription>
          </DialogHeader>
          <div className="divide-y rounded-md border">
            {[
              ['Ctrl/Cmd + S', 'Save the diagram'],
              ['Ctrl/Cmd + Z', 'Undo the last change'],
              ['Ctrl/Cmd + Shift + Z or Ctrl/Cmd + Y', 'Redo the last undone change'],
              ['Ctrl/Cmd + A', 'Select all nodes and edges'],
              ['Ctrl/Cmd + C', 'Copy selected nodes'],
              ['Ctrl/Cmd + V', 'Paste copied nodes or clipboard text into a selected node'],
              ['Ctrl/Cmd + D', 'Duplicate selected nodes'],
              ['Delete / Backspace', 'Delete selected nodes or edges'],
              ['Escape', 'Deselect and cancel the active interaction'],
            ].map(([shortcut, description]) => (
              <div key={shortcut} className="flex items-center justify-between gap-4 px-3 py-2 text-sm">
                <kbd className="rounded border bg-muted px-2 py-1 font-mono text-xs whitespace-nowrap">{shortcut}</kbd>
                <span className="text-right text-muted-foreground">{description}</span>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export function DFDEditor() {
  return (
    <ReactFlowProvider>
      <DFDEditorContent />
    </ReactFlowProvider>
  )
}
