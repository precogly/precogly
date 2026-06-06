import { useCallback, useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { applyNodeChanges, applyEdgeChanges } from '@xyflow/react'
import type { NodeChange, EdgeChange } from '@xyflow/react'
import type { Diagram, DiagramNode, DiagramEdge } from '../types'
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
  saveNow: () => Promise<void>
  updateTitle: (title: string) => Promise<void>
  // Undo feature - remove this line to disable undo functionality
  undo: () => void

  // State
  hasUnsavedChanges: boolean
  lastSaved: Date | null
  // Undo feature - remove this line to disable undo functionality
  canUndo: boolean
}

async function fetchDiagram(diagramId: string): Promise<Diagram> {
  return api.get<Diagram>(`/diagrams/${diagramId}/`)
}

async function saveDiagram(
  diagramId: string,
  data: { nodes: DiagramNode[]; edges: DiagramEdge[] }
): Promise<Diagram> {
  return api.patch<Diagram>(`/diagrams/${diagramId}/`, {
    canvas_data: {
      nodes: data.nodes,
      edges: data.edges,
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
  const { pushToHistory, undo: undoFromHistory, canUndo } = useUndoHistory()
  const nodesRef = useRef<DiagramNode[]>(nodes)
  const edgesRef = useRef<DiagramEdge[]>(edges)
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
    mutationFn: (data: { nodes: DiagramNode[]; edges: DiagramEdge[] }) =>
      saveDiagram(diagramId, data),
    onSuccess: (updatedDiagram) => {
      queryClient.setQueryData(['diagram', diagramId], updatedDiagram)
      // Invalidate delete preview cache since component sync may have changed
      queryClient.invalidateQueries({ queryKey: ['dfd-delete-preview', diagramId] })
      // Invalidate related queries so Threat Analysis and other views get fresh data
      const threatModelId = String(updatedDiagram.threatModel)
      queryClient.invalidateQueries({ queryKey: ['threat-models', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['threat-model-threats', threatModelId] })
      queryClient.invalidateQueries({ queryKey: ['components', 'analysis', threatModelId] })
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
          const edgeBackendKeys = [
            'dataflowId', 'trustBoundaryId', 'crossesBoundaryIds',
            // Snake_case variants from backend
            'trust_boundary_id',
          ] as const
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
    // Undo feature - push to history before meaningful changes
    if (hasRealChanges) {
      pushToHistory({ nodes: nodesRef.current, edges: edgesRef.current })
    }
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
      saveMutation.mutate({ nodes, edges })
    }, autoSaveInterval)

    return () => clearTimeout(timer)
  }, [nodes, edges, hasUnsavedChanges, autoSaveInterval, saveMutation])

  // Save now function
  const saveNow = useCallback(async () => {
    await saveMutation.mutateAsync({ nodes, edges })
  }, [nodes, edges, saveMutation])

  // Update title function
  const updateTitle = useCallback(async (title: string) => {
    await titleMutation.mutateAsync(title)
  }, [titleMutation])

  // Undo feature - remove this block to disable undo functionality
  const undo = useCallback(() => {
    const previousState = undoFromHistory()
    if (previousState) {
      setNodes(previousState.nodes)
      setEdges(previousState.edges)
      setHasUnsavedChanges(true)
    }
  }, [undoFromHistory])

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
    isLoading,
    isSaving: saveMutation.isPending,
    isError,
    error: error as Error | null,
    setNodes,
    setEdges,
    onNodesChange: handleNodesChange,
    onEdgesChange: handleEdgesChange,
    saveNow,
    updateTitle,
    // Undo feature - remove these lines to disable undo functionality
    undo,
    canUndo: canUndo(),
    hasUnsavedChanges,
    lastSaved,
  }
}
