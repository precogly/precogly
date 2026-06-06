import { useCallback, useState, useEffect, useRef } from 'react'
import type { XYPosition } from '@xyflow/react'
import type { DiagramNode, DiagramEdge, TrustBoundaryEdge } from '../types'

/**
 * Manages trust boundary creation interaction mode.
 * Returns boundary state and handlers for composing into DFDEditor.
 */
export function useBoundaryMode({
  nodes,
  setEdges,
  getEdges,
  getAbsolutePosition,
}: {
  nodes: DiagramNode[]
  setEdges: React.Dispatch<React.SetStateAction<DiagramEdge[]>>
  getEdges: () => DiagramEdge[]
  getAbsolutePosition: (nodeId: string) => XYPosition | null
}) {
  const [boundaryMode, setBoundaryMode] = useState(false)
  const [boundarySourceId, setBoundarySourceId] = useState<string | null>(null)
  // Track next available boundary display index for THIS diagram
  // Computed from current edges so it resets when diagram changes
  const [nextBoundaryIndex, setNextBoundaryIndex] = useState(1)

  // Refs for boundary mode — avoids stale closure issues in handleNodeClick
  // when React Flow fires onPaneClick alongside onNodeClick for container nodes
  const boundaryModeRef = useRef(false)
  const boundarySourceIdRef = useRef<string | null>(null)
  const nextBoundaryIndexRef = useRef(nextBoundaryIndex)
  useEffect(() => { boundaryModeRef.current = boundaryMode }, [boundaryMode])
  useEffect(() => { boundarySourceIdRef.current = boundarySourceId }, [boundarySourceId])
  useEffect(() => { nextBoundaryIndexRef.current = nextBoundaryIndex }, [nextBoundaryIndex])

  // Clear boundary source when boundary mode is turned off
  useEffect(() => {
    if (!boundaryMode) {
      setBoundarySourceId(null)
    }
  }, [boundaryMode])

  // Sync boundary index when diagram loads (nodes.length changes)
  useEffect(() => {
    const currentBoundaries = getEdges().filter((e) => e.type === 'trustBoundary')
    if (currentBoundaries.length === 0) {
      setNextBoundaryIndex(1)
      return
    }
    setNextBoundaryIndex(currentBoundaries.length + 1)
  }, [nodes.length])

  // Enable boundary mode only when there are at least 2 trust zones
  const enableBoundaryMode = useCallback(
    (enabled: boolean) => {
      if (enabled) {
        const trustZoneCount = nodes.filter((n) => n.type === 'trustZone').length
        if (trustZoneCount < 2) return
      }
      setBoundaryMode(enabled)
    },
    [nodes]
  )

  // Get boundary source zone info for overlay rendering
  const boundarySourceZoneInfo = (() => {
    if (!boundaryMode || !boundarySourceId) return null
    const sourceZone = nodes.find((n) => n.id === boundarySourceId)
    if (!sourceZone) return null
    const sourceZonePos = getAbsolutePosition(boundarySourceId)
    if (!sourceZonePos) return null
    return {
      position: sourceZonePos,
      width: (sourceZone.style?.width as number) || 300,
      height: (sourceZone.style?.height as number) || 200,
    }
  })()

  /**
   * Handle node click in boundary mode.
   * Returns { consumed: true, selectedEdge } if click was consumed.
   * Returns { consumed: false } if boundary mode is not active.
   */
  const handleNodeClickForBoundary = useCallback(
    (node: DiagramNode): { consumed: boolean; selectedEdge?: DiagramEdge } => {
      // Use refs to avoid stale closure issues with React Flow event ordering
      if (!boundaryModeRef.current) return { consumed: false }

      // Only trust zone nodes are valid targets in boundary mode
      if (node.type !== 'trustZone') return { consumed: true }

      const currentBoundarySourceId = boundarySourceIdRef.current

      if (!currentBoundarySourceId) {
        // First click: set as source
        setBoundarySourceId(node.id)
        return { consumed: true }
      }

      if (currentBoundarySourceId === node.id) {
        // Clicked same zone: ignore
        return { consumed: true }
      }

      // Check for duplicate A->B boundary using getEdges for latest data
      const currentEdges = getEdges()
      const existingBoundary = currentEdges.find(
        (e) =>
          e.type === 'trustBoundary' &&
          ((e.source === currentBoundarySourceId && e.target === node.id) ||
            (e.source === node.id && e.target === currentBoundarySourceId))
      )

      if (existingBoundary) {
        // Select existing boundary instead of creating duplicate
        setBoundaryMode(false)
        return { consumed: true, selectedEdge: existingBoundary as DiagramEdge }
      }

      // Second click: create trust boundary edge
      // Compute display ID from current boundary count to avoid stale state issues
      const currentBoundaryCount = getEdges().filter((e) => e.type === 'trustBoundary').length
      const newBoundaryDisplayId = currentBoundaryCount + 1

      const newBoundaryEdge: TrustBoundaryEdge = {
        id: `boundary-${Date.now()}`,
        source: currentBoundarySourceId,
        target: node.id,
        type: 'trustBoundary',
        data: {
          label: '',
          boundaryDisplayId: newBoundaryDisplayId,
        },
      }

      setEdges((eds) => [...eds, newBoundaryEdge])
      setBoundaryMode(false)
      // Pre-increment for next boundary to avoid async state lag
      setNextBoundaryIndex(currentBoundaryCount + 2)

      return { consumed: true, selectedEdge: newBoundaryEdge }
    },
    [getEdges, setEdges]
  )

  // Cancel boundary mode (for deselect/escape handling)
  const cancelBoundaryMode = useCallback(() => {
    setBoundarySourceId(null)
    setBoundaryMode(false)
  }, [])

  return {
    boundaryMode,
    setBoundaryMode: enableBoundaryMode,
    boundarySourceId,
    boundarySourceZoneInfo,
    handleNodeClickForBoundary,
    cancelBoundaryMode,
  }
}
