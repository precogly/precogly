import { memo } from 'react'
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Edge,
  type EdgeProps,
} from '@xyflow/react'
import { Lock, Unlock, ShieldCheck, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import { DATA_SENSITIVITY_TAG_CONFIG, type DataSensitivityTag } from '@/types/domain'
import type { DataFlowEdgeData } from '../../types'
import { getZoneColorConfig } from '../../types'

type DataFlowEdgeType = Edge<DataFlowEdgeData, 'dataFlow'>

export const DataFlowEdge = memo(function DataFlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
  animated,
}: EdgeProps<DataFlowEdgeType>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const isNewlyInserted = data?.isNewlyInserted

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        className={cn(
          'transition-all',
          selected ? '!stroke-blue-500' : '!stroke-gray-400',
          isNewlyInserted && '!stroke-green-500',
          animated && 'react-flow__edge-animated'
        )}
        style={{
          strokeWidth: selected ? 2.5 : 2,
          strokeDasharray: animated ? 5 : 0,
          filter: isNewlyInserted ? 'drop-shadow(0 0 3px rgb(34 197 94))' : undefined,
        }}
        markerEnd={selected ? 'url(#arrow-selected)' : 'url(#arrow)'}
      />

      {/* Edge labels - only show when selected or has important data */}
      <EdgeLabelRenderer>
        <div
          className={cn(
            'absolute pointer-events-auto nodrag nopan flex flex-col items-center gap-1',
            'transform -translate-x-1/2 -translate-y-1/2 transition-opacity',
            selected ? 'opacity-100' : 'opacity-70 hover:opacity-100'
          )}
          style={{
            left: labelX,
            top: labelY,
          }}
        >
          {/* Main label */}
          {data?.label && (
            <div className="px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 border border-gray-200 whitespace-nowrap">
              {data.label}
            </div>
          )}

          {/* Protocol badge */}
          {data?.protocol && (
            <div className="px-2 py-0.5 rounded text-xs bg-blue-100 text-blue-700 border border-blue-200 whitespace-nowrap flex items-center gap-1">
              <span>🔌</span>
              {data.protocol}
            </div>
          )}

          {/* Data classification badges */}
          {data?.dataClassification && data.dataClassification.length > 0 && (
            <div className="flex flex-wrap gap-1 justify-center max-w-[200px]">
              {data.dataClassification.map((classification) => (
                <div
                  key={classification}
                  className="px-1.5 py-0.5 rounded text-xs bg-purple-100 text-purple-700 border border-purple-200 whitespace-nowrap flex items-center gap-0.5"
                >
                  <span>🏷️</span>
                  {DATA_SENSITIVITY_TAG_CONFIG[classification as DataSensitivityTag]?.label || classification}
                </div>
              ))}
            </div>
          )}

          {/* Security indicators */}
          {(data?.encrypted !== undefined || data?.authenticated) && (
            <div className="flex items-center gap-1">
              {data?.encrypted !== undefined && (
                <div
                  className={cn(
                    'p-1 rounded',
                    data.encrypted
                      ? 'bg-green-100 text-green-700'
                      : 'bg-red-100 text-red-700'
                  )}
                  title={data.encrypted ? 'Encrypted' : 'Not Encrypted'}
                >
                  {data.encrypted ? (
                    <Lock className="h-3 w-3" />
                  ) : (
                    <Unlock className="h-3 w-3" />
                  )}
                </div>
              )}
              {data?.authenticated && (
                <div
                  className="p-1 rounded bg-green-100 text-green-700"
                  title="Authenticated"
                >
                  <ShieldCheck className="h-3 w-3" />
                </div>
              )}
            </div>
          )}

          {/* Zone crossing indicator */}
          {data?.crossesZoneId && (
            <div
              className="px-2 py-0.5 rounded text-xs flex items-center gap-1 whitespace-nowrap border"
              style={{
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderColor: getZoneColorConfig(data.crossesZoneColor).borderColor,
                color: getZoneColorConfig(data.crossesZoneColor).borderColor,
              }}
              title={`Crosses ${data.crossesZoneLabel || 'zone'} (TL: ${data.crossesZoneTrustLevel ?? 75})`}
            >
              <Shield className="h-3 w-3" />
              <span className="font-medium">{data.crossesZoneLabel || 'Zone'}</span>
            </div>
          )}

          {/* Boundary crossing indicator */}
          {data?.crossesBoundaryIds && data.crossesBoundaryIds.length > 0 && (
            <div
              className="px-2 py-0.5 rounded text-xs flex items-center gap-1 whitespace-nowrap border border-amber-400 bg-amber-50 text-amber-700"
              title={`Crosses ${data.crossesBoundaryIds.length} trust boundary(ies)`}
            >
              <span>⚠️</span>
              <span className="font-medium">
                {data.crossesBoundaryIds.length} boundary(ies)
              </span>
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  )
})
