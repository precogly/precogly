import { useCallback } from 'react'
import type { DiagramNode } from '../types'
import {
  MAX_PROCESS_HIERARCHY_DEPTH,
  getProcessAncestorDepth,
  getProcessDescendantDepth,
} from '../types/diagram'

interface BoundingBox {
  x: number
  y: number
  width: number
  height: number
}

// -----------------------------------------------------------------------------
// 1. Recursive Helper: Get True Absolute Position
// -----------------------------------------------------------------------------
function getAbsolutePosition(
  node: DiagramNode,
  nodesMap: Map<string, DiagramNode>
): { x: number; y: number } {
  let x = node.position.x
  let y = node.position.y
  let currentParentId = node.parentId

  // Traverse up the tree to sum up all offsets
  let iterations = 0
  while (currentParentId) {
    iterations++
    if (iterations > 100) break
    const parent = nodesMap.get(currentParentId)
    if (parent) {
      x += parent.position.x
      y += parent.position.y
      currentParentId = parent.parentId
    } else {
      break
    }
  }

  return { x, y }
}

function getAbsoluteBoundingBox(
  node: DiagramNode,
  nodesMap: Map<string, DiagramNode>
): BoundingBox {
  const { x, y } = getAbsolutePosition(node, nodesMap)

  // Prefer measured dimensions (actual rendered size) over style (may be stale/default)
  // This is important for resized boundaries where style might not be updated
  const width = node.measured?.width || (node.style?.width as number) || node.width || 150
  const height = node.measured?.height || (node.style?.height as number) || node.height || 60

  return { x, y, width, height }
}

// -----------------------------------------------------------------------------
// 2. Helper: Cycle Detection
// Prevent nesting a node into one of its own descendants
// -----------------------------------------------------------------------------
function isDescendant(
  potentialParentId: string,
  nodeId: string,
  nodesMap: Map<string, DiagramNode>
): boolean {
  let currentId: string | undefined = potentialParentId
  let iterations = 0

  while (currentId) {
    iterations++
    if (iterations > 100) return true // Assume cycle to prevent issues
    if (currentId === nodeId) return true
    const node = nodesMap.get(currentId)
    currentId = node?.parentId
  }
  return false
}

// -----------------------------------------------------------------------------
// 3. Helper: Get node depth (number of ancestors)
// -----------------------------------------------------------------------------
function getDepth(node: DiagramNode, nodesMap: Map<string, DiagramNode>): number {
  let depth = 0
  let parentId = node.parentId
  let iterations = 0

  while (parentId) {
    iterations++
    if (iterations > 100) break
    depth++
    const parent = nodesMap.get(parentId)
    parentId = parent?.parentId
  }
  return depth
}

/**
 * Check if all 4 corners of `inner` are inside `outer`.
 * This prevents mutual containment (a larger node can never fit inside a smaller one)
 * and ensures the user has fully placed the child inside the parent.
 */
function isFullyInside(inner: BoundingBox, outer: BoundingBox): boolean {
  return (
    inner.x >= outer.x &&
    inner.y >= outer.y &&
    inner.x + inner.width <= outer.x + outer.width &&
    inner.y + inner.height <= outer.y + outer.height
  )
}

export function useParentRelationships() {
  const findParentBoundary = useCallback(
    (node: DiagramNode, allNodes: DiagramNode[]): DiagramNode | null => {
      // Create a map for fast O(1) lookups during recursion
      const nodesMap = new Map(allNodes.map((n) => [n.id, n]))

      // Filter valid parent candidates:
      // - Trust zones and system scopes are always candidates
      // - Process containers (processes with existing children) are candidates
      //   only for process nodes being dragged (D2: process-only hierarchy)
      const candidates = allNodes.filter((n) => {
        if (n.id === node.id) return false
        if (n.type === 'trustZone' || n.type === 'systemScope') return true
        if (n.type === 'process' && (node.type === 'process' || node.type === 'datastore')) {
          // A process can parent another process or data store if it already
          // has children, OR if it's significantly larger than the dragged node
          // (i.e. user resized it to act as a container). We check measured
          // dimensions because NodeResizer updates measured (via ResizeObserver),
          // not style.
          const hasChildren = allNodes.some((child) => child.parentId === n.id)
          if (hasChildren) return true

          const candidateWidth = n.measured?.width || (n.style?.width as number) || 0
          const candidateHeight = n.measured?.height || (n.style?.height as number) || 0
          const nodeWidth = node.measured?.width || (node.style?.width as number) || 0
          const nodeHeight = node.measured?.height || (node.style?.height as number) || 0
          const isSignificantlyLarger = candidateWidth * candidateHeight > nodeWidth * nodeHeight * 1.5
          return isSignificantlyLarger
        }
        return false
      })

      const nodeBox = getAbsoluteBoundingBox(node, nodesMap)
      let bestMatch: DiagramNode | null = null
      let bestArea = Infinity

      for (const candidate of candidates) {
        // Cycle Check: Skip if the candidate is actually inside the node we are dragging
        if (isDescendant(candidate.id, node.id, nodesMap)) continue

        const candidateBox = getAbsoluteBoundingBox(candidate, nodesMap)

        // Check if all 4 corners of the node are inside the candidate's box.
        // This prevents mutual containment and premature locking.
        const allCornersInside = isFullyInside(nodeBox, candidateBox)

        if (allCornersInside) {
          // For process candidates, enforce max depth (D4)
          if (candidate.type === 'process') {
            const parentProcessDepth = getProcessAncestorDepth(candidate.id, allNodes) + 1
            const childProcessDepth = getProcessDescendantDepth(node.id, allNodes)
            if (parentProcessDepth + 1 + childProcessDepth > MAX_PROCESS_HIERARCHY_DEPTH) {
              continue // Would exceed max depth — skip to next candidate
            }
          }

          const area = candidateBox.width * candidateBox.height
          // Specificity: Always pick the smallest parent that fits
          if (area < bestArea) {
            bestArea = area
            bestMatch = candidate
          }
        }
      }

      return bestMatch
    },
    []
  )

  const updateParentRelationships = useCallback(
    (
      _nodes: DiagramNode[],
      setNodes: React.Dispatch<React.SetStateAction<DiagramNode[]>>
    ) => {
      setNodes((currentNodes) => {
        let hasChanges = false
        const boundariesReceivingChildren = new Set<string>()

        // Track new parent assignments to prevent circular references in same update
        const newParentAssignments = new Map<string, string | undefined>()

        // Build a live map that we update as we process nodes
        // This ensures child nodes see their parent's updated state
        const liveNodesMap = new Map(currentNodes.map((n) => [n.id, n]))

        const updatedNodes = currentNodes.map((node) => {
          // Find the best (smallest) containing parent for every node on every pass.
          // This ensures nodes always lock to the most specific container.
          const allNodesForSearch = Array.from(liveNodesMap.values())
          const newParent = findParentBoundary(node, allNodesForSearch)
          let newParentId = newParent?.id

          // Check if the potential parent is already assigned as a child of this node
          // in this same update pass (prevents A→B and B→A circular reference)
          if (newParentId && newParentAssignments.get(newParentId) === node.id) {
            newParentId = undefined // Don't assign, would create cycle
          }

          // Record this assignment for future cycle checks in same pass
          newParentAssignments.set(node.id, newParentId)

          // If nothing changed, return original reference (but clear stale extent)
          if (node.parentId === newParentId) {
            if (node.extent === 'parent') {
              hasChanges = true
              return { ...node, extent: undefined }
            }
            return node
          }

          hasChanges = true

          // Track boundaries receiving new children for animation
          if (newParentId && node.parentId !== newParentId) {
            boundariesReceivingChildren.add(newParentId)
          }

          // Coordinate Transformation
          // Calculate absolute position first, then convert to relative if there's a new parent
          const absPos = getAbsolutePosition(node, liveNodesMap)
          let newPos = { x: absPos.x, y: absPos.y }

          if (newParentId && newParent) {
            const parentAbsPos = getAbsolutePosition(newParent, liveNodesMap)
            newPos = {
              x: absPos.x - parentAbsPos.x,
              y: absPos.y - parentAbsPos.y,
            }
          }

          const updatedNode = {
            ...node,
            parentId: newParentId,
            position: newPos,
            extent: undefined, // Allow free dragging, parent relationship managed by position
            data: {
              ...node.data,
              // Trigger lock animation when entering a parent
              lockAnimationKey: newParentId ? Date.now() + Math.random() : undefined,
            },
          }

          // Update liveNodesMap so subsequent nodes see this node's new state
          liveNodesMap.set(node.id, updatedNode)

          return updatedNode
        })

        if (!hasChanges) return currentNodes

        // Update boundaries that received children (for receive animation + auto-sizing)
        const finalNodes = updatedNodes.map((node) => {
          if (
            (node.type === 'trustZone' || node.type === 'systemScope' || node.type === 'process') &&
            boundariesReceivingChildren.has(node.id)
          ) {
            // React Flow sub-flows require parent nodes to have style.width/height.
            // NodeResizer updates measured (via ResizeObserver), not style, so we
            // must ensure style dimensions are always set on process parents.
            let styleUpdate: Record<string, unknown> | undefined
            if (node.type === 'process') {
              const hasStyleSize = node.style?.width && node.style?.height
              if (!hasStyleSize) {
                // Copy measured dimensions to style, or use default container size
                const width = node.measured?.width || 350
                const height = node.measured?.height || 250
                styleUpdate = { style: { ...node.style, width, height } }
              }
            }
            return {
              ...node,
              ...styleUpdate,
              data: {
                ...node.data,
                receiveChildAnimationKey: Date.now() + Math.random(),
              },
            }
          }
          return node
        })

        // Topological Sort: Parents must be before children in the array
        // This ensures proper z-indexing and React Flow rendering order
        const updatedNodesMap = new Map(finalNodes.map((n) => [n.id, n]))

        // Set explicit zIndex based on depth so children always render on top of parents
        const sortedNodes = [...finalNodes]
          .sort(
            (a, b) => getDepth(a, updatedNodesMap) - getDepth(b, updatedNodesMap)
          )
          .map((node) => {
            const depth = getDepth(node, updatedNodesMap)
            if (depth > 0 && node.zIndex !== depth) {
              return { ...node, zIndex: depth }
            }
            if (depth === 0 && node.zIndex !== undefined) {
              return { ...node, zIndex: undefined }
            }
            return node
          })

        return sortedNodes
      })
    },
    [findParentBoundary]
  )

  return { updateParentRelationships, findParentBoundary }
}
