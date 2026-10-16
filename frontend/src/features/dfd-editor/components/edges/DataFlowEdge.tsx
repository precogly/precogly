import { memo, useCallback, useEffect, useRef, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
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
import { getAuthentication, getFlowType, isAuthenticated } from '../../lib/canvas-defaults'
import {
  FLOW_TYPE_STYLES,
  flowTypeShortLabel,
  isFlowTypeVisible,
  showsFlowTypeChip,
} from '../../lib/flow-visibility'
import { getTrustLevel } from '../../lib/zone-trust-level'
import { useDFDNotation } from '../../context/DFDNotationContext'

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
  const { setEdges } = useReactFlow()
  const { visibleFlowTypes } = useDFDNotation()
  const flowType = getFlowType(data)
  const flowTypeStyle = FLOW_TYPE_STYLES[flowType]
  const flowIsAuthenticated = isAuthenticated(getAuthentication(data))
  const [editValue, setEditValue] = useState(data?.label || '')
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const originalLabelRef = useRef(data?.label || '')
  const skipBlurRef = useRef(false)
  const isEditing = Boolean(data?.isInlineEditing)

  useEffect(() => {
    if (!isEditing) return

    originalLabelRef.current = data?.label || ''
    skipBlurRef.current = false
    setEditValue(originalLabelRef.current)
    requestAnimationFrame(() => {
      if (!inputRef.current) return
      inputRef.current.style.height = 'auto'
      inputRef.current.style.height = `${inputRef.current.scrollHeight}px`
      inputRef.current.focus()
      inputRef.current.select()
    })
  }, [isEditing, data?.label])

  const finishEditing = useCallback((commit: boolean) => {
    setEdges((edges) => edges.map((edge) =>
      edge.id === id
        ? {
            ...edge,
            data: {
              ...edge.data,
              label: commit ? editValue.trim() : originalLabelRef.current,
              isInlineEditing: false,
            },
          }
        : edge
    ))
  }, [editValue, id, setEdges])

  const commitOnBlur = useCallback(() => {
    if (skipBlurRef.current) {
      skipBlurRef.current = false
      return
    }
    finishEditing(true)
  }, [finishEditing])

  const startEditing = useCallback((event: React.MouseEvent) => {
    event.stopPropagation()
    setEdges((edges) => edges.map((edge) => {
      if (edge.type !== 'dataFlow') return edge
      return {
        ...edge,
        data: { ...edge.data, isInlineEditing: edge.id === id },
      }
    }))
  }, [id, setEdges])

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const isNewlyInserted = data?.isNewlyInserted

  // The flow type filter (the "physical view", plan F22): a flow whose type
  // is unticked is not drawn. It stays in the canvas data untouched.
  if (!isFlowTypeVisible(flowType, visibleFlowTypes)) return null

  // Data flows keep the short animated dash; every other type has its own
  // pattern so a signal or control flow is told apart without the chip.
  const strokeDasharray = flowTypeStyle.strokeDasharray ?? (animated ? '5' : '0')

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
          strokeWidth: selected ? flowTypeStyle.strokeWidth + 0.5 : flowTypeStyle.strokeWidth,
          strokeDasharray,
          filter: isNewlyInserted ? 'drop-shadow(0 0 3px rgb(34 197 94))' : undefined,
        }}
        markerEnd={selected ? 'url(#arrow-selected)' : 'url(#arrow)'}
        onDoubleClick={startEditing}
      />

      {/* Edge labels - only show when selected or has important data */}
      <EdgeLabelRenderer>
        <div
          data-id={id}
          className={cn(
            'absolute pointer-events-auto nodrag nopan flex flex-col items-center gap-1',
            'transform -translate-x-1/2 -translate-y-1/2 transition-opacity',
            selected ? 'opacity-100' : 'opacity-100'
          )}
          style={{
            left: labelX,
            top: labelY,
          }}
        >
          {/* Main label */}
          {(data?.label || selected || isEditing) && (
            isEditing ? (
              <textarea
                ref={inputRef}
                value={editValue}
                rows={1}
                placeholder="Flow label"
                onChange={(event) => {
                  setEditValue(event.target.value)
                  event.target.style.height = 'auto'
                  event.target.style.height = `${event.target.scrollHeight}px`
                }}
                onKeyDown={(event) => {
                  event.stopPropagation()
                  if (event.key === 'Escape') {
                    event.preventDefault()
                    skipBlurRef.current = true
                    finishEditing(false)
                  } else if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault()
                    skipBlurRef.current = true
                    finishEditing(true)
                  }
                }}
                onBlur={commitOnBlur}
                onClick={(event) => event.stopPropagation()}
                onMouseDown={(event) => event.stopPropagation()}
                className="nodrag nopan nowheel min-w-24 resize-none overflow-hidden rounded border border-blue-400 bg-white px-2 py-0.5 text-xs text-gray-950 outline-none"
              />
            ) : (
              <div
                className="cursor-text rounded border border-gray-300 bg-white px-2 py-0.5 text-center text-xs font-medium text-gray-950 shadow-sm whitespace-pre-line break-words max-w-[240px]"
                onDoubleClick={startEditing}
                title="Double-click to edit"
              >
                {data?.label || 'Double-click to add label'}
              </div>
            )
          )}

          {/* Flow type chip: every type except data */}
          {showsFlowTypeChip(flowType) && (
            <div
              className={cn(
                'px-1.5 py-px rounded text-[10px] uppercase tracking-wide border whitespace-nowrap',
                flowTypeStyle.chipClassName
              )}
              title={`${flowTypeShortLabel(flowType)} flow`}
              data-testid="flow-type-chip"
            >
              {flowTypeShortLabel(flowType)}
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
          {(data?.encrypted !== undefined || flowIsAuthenticated) && (
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
              {flowIsAuthenticated && (
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
              title={(() => {
                const crossedLevel = getTrustLevel({ trustLevel: data.crossesZoneTrustLevel })
                const levelText = crossedLevel === null ? '' : ` (TL: ${crossedLevel})`
                return `Crosses ${data.crossesZoneLabel || 'zone'}${levelText}`
              })()}
            >
              <Shield className="h-3 w-3" />
              <span className="font-medium">{data.crossesZoneLabel || 'Zone'}</span>
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  )
})
