import { useCallback, useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { applyNodeChanges, applyEdgeChanges } from '@xyflow/react'
import type { NodeChange, EdgeChange } from '@xyflow/react'
import type { Diagram, DiagramNode, DiagramEdge } from '../types'
import type { DFDNotationStyle } from '../types/notation'
import type { FlowType } from '@/types/domain'
import { api } from '@/lib/api'
// Undo feature - remove this import to disable undo functionality
import { useUndoHistory } from './useUndoHistory'

interface UseDiagramStateOptions {
  diagramId: string
  autoSaveInterval?: number // ms, 0 to disable
}

interface UseDiagramStateReturn {
  // Data
  diagram: Diagram | undefined
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  initialNotationStyle: DFDNotationStyle
  /** The flow type filter loaded with the diagram; missing means every type (plan F22). */
  initialVisibleFlowTypes: FlowType[] | undefined

  // Loading states
  isLoading: boolean
  isSaving: boolean
  isError: boolean
  error: Error | null

  // Actions
  setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>>
  setEdges: React.Dispatch<React.SetStateAction<DiagramEdge[]>>
  onNodesChange: (changes: NodeChange<DiagramNode>[]) => void
  onEdgesChange: (changes: EdgeChange<DiagramEdge>[]) => void
  saveNow: (notationStyle?: DFDNotationStyle) => Promise<void>
  /** Store the flow type filter on the canvas root; saved with the next save. */
  setVisibleFlowTypes: (visibleFlowTypes: FlowType[] | undefined) => void
  updateTitle: (title: string) => Promise<void>
  // Undo feature - remove this line to disable undo functionality
  undo: () => void
  redo: () => void

  // State
  hasUnsavedChanges: boolean
  lastSaved: Date | null
  // Undo feature - remove this line to disable undo functionality
  canUndo: boolean
  canRedo: boolean
}

async function fetchDiagram(diagramId: string): Promise<Diagram> {
  return api.get<Diagram>(`/diagrams/${diagramId}/`)
}

/** Strip transient UI flags from node data before persisting. */
function stripTransientNodeFlags(nodes: DiagramNode[]): DiagramNode[] {
  return nodes.map((node) => {
    const { isInlineEditing, isNewlyInserted, ...rest } = node.data
    return isInlineEditing || isNewlyInserted
      ? { ...node, data: { ...rest, label: node.data.label } as typeof node.data }
      : node
  })
}

interface SaveDiagramData {
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  notationStyle?: DFDNotationStyle
  visibleFlowTypes?: FlowType[]
  /** The blueprint the diagram belongs to: read-only server side, sent as context (plan 11.2). */
  blueprint?: number
}

async function saveDiagram(diagramId: string, data: SaveDiagramData): Promise<Diagram> {
  return api.patch<Diagram>(`/diagrams/${diagramId}/`, {
    blueprint: data.blueprint,
    canvas_data: {
      nodes: stripTransientNodeFlags(data.nodes),
      edges: data.edges,
      notationStyle: data.notationStyle,
      visibleFlowTypes: data.visibleFlowTypes,
    },
  })
}

async function updateDiagramTitle(
  diagramId: string,
  title: string
): Promise<Diagram> {
  return api.patch<Diagram>(`/diagrams/${diagramId}/`, { name: title })
}

export function useDiagramState({
  diagramId,
  autoSaveInterval = 30000, // 30 seconds default
}: UseDiagramStateOptions): UseDiagramStateReturn {
  const queryClient = useQueryClient()

  // Local state for nodes and edges
  const [nodes, setNodesInternal] = useState<DiagramNode[]>([])
  const [edges, setEdgesInternal] = useState<DiagramEdge[]>([])
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)
  const [initialNotationStyle, setInitialNotationStyle] = useState<DFDNotationStyle>('yourdon')
  const notationStyleRef = useRef<DFDNotationStyle>('yourdon')
  const [initialVisibleFlowTypes, setInitialVisibleFlowTypes] = useState<FlowType[] | undefined>(undefined)
  const visibleFlowTypesRef = useRef<FlowType[] | undefined>(undefined)

  // Track if initial data has been loaded
  const initialLoadRef = useRef(false)

  // Wrap setNodes to also mark as changed (after initial load)
  const setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>> = useCallback(
    (value) => {
      setNodesInternal(value)
      if (initialLoadRef.current) {
        setHasUnsavedChanges(true)
      }
    },
    []
  )

  // Wrap setEdges to also mark as changed (after initial load)
  const setEdges: React.Dispatch<React.SetStateAction<DiagramEdge[]>> = useCallback(
    (value) => {
      setEdgesInternal(value)
      if (initialLoadRef.current) {
        setHasUnsavedChanges(true)
      }
    },
    []
  )

  // Undo feature - remove this block to disable undo functionality
  const { pushToHistory, undo: undoFromHistory, redo: redoFromHistory, canUndo, canRedo } = useUndoHistory()
  const nodesRef = useRef<DiagramNode[]>(nodes)
  const edgesRef = useRef<DiagramEdge[]>(edges)
  const nodeDragHistoryRef = useRef(false)
  // Keep refs in sync for undo access
  useEffect(() => {
    nodesRef.current = nodes
    edgesRef.current = edges
  }, [nodes, edges])

  // Fetch diagram data
  const {
    data: diagram,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['diagram', diagramId],
    queryFn: () => fetchDiagram(diagramId),
    staleTime: 60000, // Consider fresh for 1 minute
  })

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (data: SaveDiagramData) => saveDiagram(diagramId, data),
    onSuccess: (updatedDiagram) => {
      queryClient.setQueryData(['diagram', diagramId], updatedDiagram)
      // Invalidate delete preview cache since component sync may have changed
      queryClient.invalidateQueries({ queryKey: ['dfd-delete-preview', diagramId] })
      // Invalidate related queries so Threat Analysis and other views get fresh data
      const threatModelId = String(updatedDiagram.threatModel)
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['components', 'analysis', threatModelId] })
      // The blueprint-scoped rows sync rewrote: zones, boundaries, flows
      // (useZones, useBoundaries, useFlows key on these roots).
      queryClient.invalidateQueries({ queryKey: ['zones'] })
      queryClient.invalidateQueries({ queryKey: ['boundaries'] })
      queryClient.invalidateQueries({ queryKey: ['flows'] })
      // Invalidate risk queries (technology changes CASCADE-delete RiskThreat links)
      queryClient.invalidateQueries({ queryKey: ['risks'] })

      // Merge backend-generated IDs (componentId, trustZoneId, orgsystemId)
      // back into local node state so features like Data Assets become available
      // without requiring a page reload
      const savedNodes = (updatedDiagram.canvasData?.nodes || []) as DiagramNode[]
      const savedNodeMap = new Map(
        savedNodes.map((n) => [n.id, n.data])
      )
      setNodesInternal((currentNodes) =>
        currentNodes.map((node) => {
          const savedData = savedNodeMap.get(node.id)
          if (!savedData) return node
          const backendKeys = ['componentId', 'trustZoneId', 'orgsystemId'] as const
          let updated = false
          const mergedData = { ...node.data }
          for (const key of backendKeys) {
            if (key in savedData && (savedData as Record<string, unknown>)[key] !== (node.data as Record<string, unknown>)[key]) {
              ;(mergedData as Record<string, unknown>)[key] = (savedData as Record<string, unknown>)[key]
              updated = true
            }
          }
          return updated ? { ...node, data: mergedData } : node
        })
      )

      // Merge backend-generated dataflow_id into local edge state
      const savedEdges = (updatedDiagram.canvasData?.edges || []) as DiagramEdge[]
      const savedEdgeMap = new Map(
        savedEdges.map((e) => [e.id, e.data])
      )
      setEdgesInternal((currentEdges) =>
        currentEdges.map((edge) => {
          const savedData = savedEdgeMap.get(edge.id)
          if (!savedData) return edge
          const edgeBackendKeys = ['dataflowId', 'trustBoundaryId'] as const
          let updated = false
          const mergedData = { ...edge.data }
          for (const key of edgeBackendKeys) {
            if (key in savedData && (savedData as Record<string, unknown>)[key] !== (edge.data as Record<string, unknown>)[key]) {
              ;(mergedData as Record<string, unknown>)[key] = (savedData as Record<string, unknown>)[key]
              updated = true
            }
          }
          return updated ? { ...edge, data: mergedData } : edge
        })
      )

      setHasUnsavedChanges(false)
      setLastSaved(new Date())
    },
  })

  // Title update mutation
  const titleMutation = useMutation({
    mutationFn: (title: string) => updateDiagramTitle(diagramId, title),
    onSuccess: (updatedDiagram) => {
      queryClient.setQueryData(['diagram', diagramId], updatedDiagram)
    },
  })

  // Initialize nodes and edges from fetched diagram
  useEffect(() => {
    if (diagram && !initialLoadRef.current) {
      const canvasData = diagram.canvasData
      // Use internal setters during initial load to avoid marking as changed
      setNodesInternal((canvasData?.nodes || []) as DiagramNode[])
      setEdgesInternal((canvasData?.edges || []) as DiagramEdge[])
      const loadedNotation = canvasData?.notationStyle ?? 'yourdon'
      setInitialNotationStyle(loadedNotation)
      notationStyleRef.current = loadedNotation
      const loadedVisibleFlowTypes = Array.isArray(canvasData?.visibleFlowTypes)
        ? canvasData.visibleFlowTypes
        : undefined
      setInitialVisibleFlowTypes(loadedVisibleFlowTypes)
      visibleFlowTypesRef.current = loadedVisibleFlowTypes
      const updatedAt = diagram.updatedAt
      if (updatedAt) setLastSaved(new Date(updatedAt))
      initialLoadRef.current = true
    }
  }, [diagram])

  // Reset initial load ref when diagram ID changes
  useEffect(() => {
    initialLoadRef.current = false
  }, [diagramId])

  // Track changes to nodes
  const handleNodesChange = useCallback((changes: NodeChange<DiagramNode>[]) => {
    // Only mark as changed for meaningful changes (not selection)
    const hasRealChanges = changes.some(
      (c) => c.type !== 'select' && c.type !== 'dimensions'
    )
    const hasDraggingChange = changes.some(
      (c) => c.type === 'position' && c.dragging === true
    )
    const hasPositionChange = changes.some((c) => c.type === 'position')
    const endsDragging = changes.some(
      (c) => c.type === 'position' && c.dragging === false
    )
    // Undo feature - push to history before meaningful changes
    if (hasRealChanges) {
      if (hasDraggingChange) {
        if (!nodeDragHistoryRef.current) {
          pushToHistory({ nodes: nodesRef.current, edges: edgesRef.current })
        }
        nodeDragHistoryRef.current = true
      } else if (!hasPositionChange || !nodeDragHistoryRef.current) {
        pushToHistory({ nodes: nodesRef.current, edges: edgesRef.current })
      }
    }
    if (endsDragging) nodeDragHistoryRef.current = false
    // Use internal setter - we handle hasUnsavedChanges manually for selective detection
    setNodesInternal((nds) => applyNodeChanges(changes, nds) as DiagramNode[])
    if (hasRealChanges) {
      setHasUnsavedChanges(true)
    }
  }, [pushToHistory])

  // Track changes to edges
  const handleEdgesChange = useCallback((changes: EdgeChange<DiagramEdge>[]) => {
    // Only mark as changed for meaningful changes
    const hasRealChanges = changes.some((c) => c.type !== 'select')
    // Undo feature - push to history before meaningful changes
    if (hasRealChanges) {
      pushToHistory({ nodes: nodesRef.current, edges: edgesRef.current })
    }
    // Use internal setter - we handle hasUnsavedChanges manually for selective detection
    setEdgesInternal((eds) => applyEdgeChanges(changes, eds) as DiagramEdge[])
    if (hasRealChanges) {
      setHasUnsavedChanges(true)
    }
  }, [pushToHistory])

  // Auto-save effect
  useEffect(() => {
    if (autoSaveInterval <= 0 || !hasUnsavedChanges) return

    const timer = setTimeout(() => {
      saveMutation.mutate({
        nodes,
        edges,
        notationStyle: notationStyleRef.current,
        visibleFlowTypes: visibleFlowTypesRef.current,
        blueprint: diagram?.blueprint,
      })
    }, autoSaveInterval)

    return () => clearTimeout(timer)
  }, [nodes, edges, hasUnsavedChanges, autoSaveInterval, saveMutation, diagram?.blueprint])

  // Save now function: accepts an optional notationStyle override to capture the latest value
  const saveNow = useCallback(async (currentNotationStyle?: DFDNotationStyle) => {
    const styleToSave = currentNotationStyle ?? notationStyleRef.current
    notationStyleRef.current = styleToSave
    await saveMutation.mutateAsync({
      nodes,
      edges,
      notationStyle: styleToSave,
      visibleFlowTypes: visibleFlowTypesRef.current,
      blueprint: diagram?.blueprint,
    })
  }, [nodes, edges, saveMutation, diagram?.blueprint])

  // The flow type filter is canvas data (plan F22): changing it is a change to save.
  const setVisibleFlowTypes = useCallback((visibleFlowTypes: FlowType[] | undefined) => {
    visibleFlowTypesRef.current = visibleFlowTypes
    setHasUnsavedChanges(true)
  }, [])

  // Update title function
  const updateTitle = useCallback(async (title: string) => {
    await titleMutation.mutateAsync(title)
  }, [titleMutation])

  // Undo feature - remove this block to disable undo functionality
  const undo = useCallback(() => {
    const previousState = undoFromHistory({ nodes: nodesRef.current, edges: edgesRef.current })
    if (previousState) {
      setNodes(previousState.nodes)
      setEdges(previousState.edges)
      setHasUnsavedChanges(true)
    }
  }, [undoFromHistory, setNodes, setEdges])

  const redo = useCallback(() => {
    const nextState = redoFromHistory({ nodes: nodesRef.current, edges: edgesRef.current })
    if (nextState) {
      setNodes(nextState.nodes)
      setEdges(nextState.edges)
      setHasUnsavedChanges(true)
    }
  }, [redoFromHistory, setNodes, setEdges])

  // Warn before leaving with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChanges) {
        e.preventDefault()
        e.returnValue = ''
      }
    }

    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => window.removeEventListener('beforeunload', handleBeforeUnload)
  }, [hasUnsavedChanges])

  return {
    diagram,
    nodes,
    edges,
    initialNotationStyle,
    initialVisibleFlowTypes,
    isLoading,
    isSaving: saveMutation.isPending,
    isError,
    error: error as Error | null,
    setNodes,
    setEdges,
    onNodesChange: handleNodesChange,
    onEdgesChange: handleEdgesChange,
    saveNow,
    setVisibleFlowTypes,
    updateTitle,
    // Undo feature - remove these lines to disable undo functionality
    undo,
    canUndo: canUndo(),
    redo,
    canRedo: canRedo(),
    hasUnsavedChanges,
    lastSaved,
  }
}
