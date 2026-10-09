import { memo } from 'react'
import {
  BaseEdge,
  EdgeLabelRenderer,
  type Edge,
  type EdgeProps,
} from '@xyflow/react'
import { Lock, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import { BOUNDARY_TYPES } from '@/types/domain'
import { isAuthenticated, requiresAuthorization } from '@/lib/authentication'
import type { TrustBoundaryEdgeData } from '../../types'
import { getBoundaryType } from '../../lib/canvas-defaults'

type TrustBoundaryEdgeType = Edge<TrustBoundaryEdgeData, 'trustBoundary'>

/**
 * Determine security posture color based on the crossing requirements.
 * - Red: neither authentication nor authorization recorded
 * - Amber: one of the two recorded (partial)
 * - Green: both recorded
 */
function getSecurityColor(hasAuthentication: boolean, hasAuthorization: boolean): string {
  if (hasAuthentication && hasAuthorization) return '#22c55e'
  if (hasAuthentication || hasAuthorization) return '#f59e0b'
  return '#ef4444'
}

/**
 * Boundary edge: a dividing line drawn in the gap between two zones, like a
 * fence between them. The label carries the boundary type ("Network
 * boundary") next to the user's label (plan 11.2).
 */
export const TrustBoundaryEdge = memo(function TrustBoundaryEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  data,
  selected,
}: EdgeProps<TrustBoundaryEdgeType>) {
  const hasAuthentication = isAuthenticated(data?.authenticationMethods)
  const hasAuthorization = requiresAuthorization(data?.accessControlMethods)
  const color = getSecurityColor(hasAuthentication, hasAuthorization)
  const boundaryType = getBoundaryType(data)
  const boundaryTypeLabel =
    BOUNDARY_TYPES.find((entry) => entry.value === boundaryType)?.label ?? 'Boundary'

  const dx = targetX - sourceX
  const dy = targetY - sourceY
  const isHorizontalGap = Math.abs(dx) >= Math.abs(dy)

  // Generous extension so the line spans the full height/width of the zones
  const extension = 120

  let edgePath: string
  let labelX: number
  let labelY: number

  if (isHorizontalGap) {
    // Zones are side by side: draw a vertical dividing line in the gap
    const midX = (sourceX + targetX) / 2
    const minY = Math.min(sourceY, targetY) - extension
    const maxY = Math.max(sourceY, targetY) + extension
    edgePath = `M ${midX} ${minY} L ${midX} ${maxY}`
    labelX = midX
    labelY = (sourceY + targetY) / 2 - extension - 20
  } else {
    // Zones are stacked: draw a horizontal dividing line in the gap
    const midY = (sourceY + targetY) / 2
    const minX = Math.min(sourceX, targetX) - extension
    const maxX = Math.max(sourceX, targetX) + extension
    edgePath = `M ${minX} ${midY} L ${maxX} ${midY}`
    labelX = (sourceX + targetX) / 2
    labelY = midY - 20
  }

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        className={cn(
          'transition-all',
          selected && '!stroke-blue-500'
        )}
        style={{
          stroke: selected ? undefined : color,
          strokeWidth: selected ? 3 : 2.5,
          strokeDasharray: '10 6',
          strokeLinecap: 'round',
        }}
      />

      <EdgeLabelRenderer>
        <div
          data-id={id}
          className={cn(
            'absolute pointer-events-auto nodrag nopan flex items-center gap-1.5',
            'transform -translate-x-1/2 transition-opacity',
            selected ? 'opacity-100' : 'opacity-70 hover:opacity-100'
          )}
          style={{
            left: labelX,
            top: labelY,
          }}
        >
          {/* Security badge icons */}
          {hasAuthentication && (
            <div
              className="p-1 rounded"
              style={{ backgroundColor: `${color}20`, color }}
              title="Authentication required"
            >
              <Lock className="h-3 w-3" />
            </div>
          )}
          {hasAuthorization && (
            <div
              className="p-1 rounded"
              style={{ backgroundColor: `${color}20`, color }}
              title="Authorization required"
            >
              <ShieldCheck className="h-3 w-3" />
            </div>
          )}

          {/* Boundary type, then the label when there is one */}
          <div
            className="px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap border flex items-center gap-1.5"
            style={{
              backgroundColor: `${color}15`,
              borderColor: color,
              color,
            }}
            data-testid="boundary-label"
          >
            <span
              className="text-[10px] uppercase tracking-wide opacity-80"
              data-testid="boundary-type-label"
            >
              {boundaryTypeLabel}
            </span>
            {data?.label && <span>{data.label}</span>}
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  )
})
