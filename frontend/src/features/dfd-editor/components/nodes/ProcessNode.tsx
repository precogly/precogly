import { memo, useCallback, useEffect, useState } from 'react'
import { Handle, Position, NodeResizer, useStore, type Node, type NodeProps } from '@xyflow/react'
import { Cog } from 'lucide-react'
import { cn } from '@/lib/utils'
import { InlineEditableLabel } from './InlineEditableLabel'
import type { ProcessNodeData } from '../../types'
import { DATA_SENSITIVITY_CONFIG } from '../../types'
import { useTechnologyInfo } from '../../api/component-library'
import { useDFDNotation } from '../../context/DFDNotationContext'

type ProcessNodeType = Node<ProcessNodeData, 'process'>

const HANDLE_CLASS = '!bg-blue-500 !w-2 !h-2 !min-w-0 !min-h-0'

/** Shared handles for both leaf and container modes.
 *  Process nodes keep 8 named handles in both modes
 *  (unlike trust zones which have 4) because they still
 *  participate in data flows. */
function ProcessHandles() {
  return (
    <>
      {/* Top */}
      <Handle id="top-target" type="target" position={Position.Top} className={HANDLE_CLASS} />
      <Handle id="top-source" type="source" position={Position.Top} className={HANDLE_CLASS} />
      {/* Right */}
      <Handle id="right-target" type="target" position={Position.Right} className={HANDLE_CLASS} />
      <Handle id="right-source" type="source" position={Position.Right} className={HANDLE_CLASS} />
      {/* Bottom */}
      <Handle id="bottom-target" type="target" position={Position.Bottom} className={HANDLE_CLASS} />
      <Handle id="bottom-source" type="source" position={Position.Bottom} className={HANDLE_CLASS} />
      {/* Left */}
      <Handle id="left-target" type="target" position={Position.Left} className={HANDLE_CLASS} />
      <Handle id="left-source" type="source" position={Position.Left} className={HANDLE_CLASS} />
    </>
  )
}

export const ProcessNode = memo(function ProcessNode({
  id,
  data,
  selected,
}: NodeProps<ProcessNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const technologySlug = data.technology || (data as Record<string, unknown>).componentRef as string | undefined
  const { displayName: technologyDisplayName, iconSvg: technologyIcon } = useTechnologyInfo(technologySlug)
  const [showLockAnimation, setShowLockAnimation] = useState(false)
  const [showReceiveAnimation, setShowReceiveAnimation] = useState(false)
  const { notationStyle } = useDFDNotation()

  // Check if this process has children (makes it a container)
  const isContainer = useStore(
    useCallback(
      (state) => state.nodes.some((n) => n.parentId === id),
      [id]
    )
  )

  // Trigger lock animation when lockAnimationKey changes
  useEffect(() => {
    if (data.lockAnimationKey) {
      setShowLockAnimation(true)
      const timer = setTimeout(() => setShowLockAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.lockAnimationKey])

  // Trigger receive-child animation when receiveChildAnimationKey changes
  useEffect(() => {
    if (data.receiveChildAnimationKey) {
      setShowReceiveAnimation(true)
      const timer = setTimeout(() => setShowReceiveAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.receiveChildAnimationKey])

  const isYourdon = notationStyle === 'yourdon' && !isContainer

  // ── Unified render path ──
  // Always renders the same DOM structure (NodeResizer → Handles → div) regardless
  // of leaf/container mode. This mirrors TrustZoneNode's always-container pattern
  // and prevents React Flow from losing parent-child state during DOM transitions.
  return (
    <>
      <NodeResizer
        minWidth={isContainer ? 250 : isYourdon ? 60 : 120}
        minHeight={isContainer ? 180 : isYourdon ? 60 : 50}
        keepAspectRatio={isYourdon}
        isVisible={selected}
        lineClassName="!border-solid"
        handleClassName="!w-2 !h-2 !rounded-sm"
        lineStyle={{ borderColor: '#3b82f6' }}
        handleStyle={{ backgroundColor: '#3b82f6', borderColor: '#3b82f6' }}
      />
      <ProcessHandles />
      <div
        className={cn(
          'w-full transition-all',
          isContainer ? 'h-full' : 'min-h-full',
          isContainer
            ? cn(
                'border-2 rounded-lg border-solid',
                selected ? 'border-blue-500 shadow-md' : 'border-blue-300',
                showReceiveAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
              )
            : technologyIcon
              ? cn(
                  'flex flex-col items-center justify-center p-1',
                  selected && 'shadow-lg',
                  showLockAnimation && 'animate-lock-pulse'
                )
              : isYourdon
                ? cn(
                    'border-2 rounded-full bg-blue-50 flex flex-col items-center justify-center',
                    selected ? 'border-blue-500 shadow-md' : 'border-blue-200',
                    showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
                  )
                : cn(
                    'border-2 rounded-lg px-4 py-3 bg-blue-50 min-w-[120px] flex items-center',
                    selected ? 'border-blue-500 shadow-md' : 'border-blue-200',
                    showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
                  ),
          isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2'
        )}
        style={isContainer ? { backgroundColor: 'rgba(219, 234, 254, 0.4)' } : undefined}
      >
        {isContainer ? (
          <>
            {/* Label badge at top-left */}
            <div className="absolute -top-3 left-3 px-2 py-0.5 rounded text-xs font-medium bg-blue-500 text-white flex items-center gap-1">
              {technologyIcon && (
                <span
                  className="h-3 w-3 [&>svg]:h-full [&>svg]:w-full"
                  dangerouslySetInnerHTML={{ __html: technologyIcon }}
                />
              )}
              <InlineEditableLabel
                nodeId={id}
                label={data.label}
                isEditing={data.isInlineEditing}
                inputClassName="max-w-[120px] text-white placeholder-white/50"
              />
            </div>
            {/* Technology badge at top-right */}
            {data.technology && (
              <div className="absolute -top-3 right-3 px-2 py-0.5 rounded text-xs bg-white text-blue-600 border border-blue-300">
                {technologyDisplayName}
              </div>
            )}
            {/* Data sensitivity badge at bottom-left */}
            {data.dataSensitivity && (
              <div
                className="absolute bottom-1 left-3 text-xs px-1.5 py-0.5 rounded"
                style={{
                  backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                  color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                }}
              >
                {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
              </div>
            )}
          </>
        ) : technologyIcon ? (
          <>
            <span
              className="h-10 w-10 [&>svg]:h-full [&>svg]:w-full"
              dangerouslySetInnerHTML={{ __html: technologyIcon }}
            />
            <InlineEditableLabel
              nodeId={id}
              label={data.label}
              isEditing={data.isInlineEditing}
              className="font-medium text-xs text-gray-900 text-center break-words max-w-[80px] mt-1"
              inputClassName="max-w-[80px] text-xs text-gray-900 text-center"
            />
            {data.dataSensitivity && (
              <span
                className="text-[10px] px-1 rounded mt-0.5"
                style={{
                  backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                  color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                }}
              >
                {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
              </span>
            )}
          </>
        ) : isYourdon ? (
          <>
            <Cog className="h-4 w-4 text-blue-600 flex-shrink-0" />
            <InlineEditableLabel
              nodeId={id}
              label={data.label}
              isEditing={data.isInlineEditing}
              className="font-medium text-xs text-blue-900 line-clamp-6 break-words max-w-[90%] text-center px-1"
              inputClassName="max-w-[90%] text-xs text-blue-900 text-center"
            />
            {data.technology && (
              <span className="text-[10px] text-blue-600 truncate max-w-[90%]">
                {technologyDisplayName}
              </span>
            )}
            {data.dataSensitivity && (
              <span
                className="text-[10px] truncate max-w-[90%] px-1 rounded"
                style={{
                  backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                  color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                }}
              >
                {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
              </span>
            )}
          </>
        ) : (
          <div className="flex flex-col min-w-0 overflow-hidden w-full">
            <div className="flex items-center gap-2 min-w-0">
              <Cog className="h-4 w-4 text-blue-600 flex-shrink-0" />
              <div className="flex flex-col min-w-0">
                <InlineEditableLabel
                  nodeId={id}
                  label={data.label}
                  isEditing={data.isInlineEditing}
                  className="font-medium text-sm text-blue-900 line-clamp-6 break-words"
                  inputClassName="text-sm text-blue-900 w-full"
                />
                {data.technology && (
                  <span className="text-xs text-blue-600 truncate">
                    {technologyDisplayName}
                  </span>
                )}
              </div>
            </div>
            {data.dataSensitivity && (
              <div
                className="mt-1 text-xs px-1.5 py-0.5 rounded text-center truncate"
                style={{
                  backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                  color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                }}
              >
                {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
              </div>
            )}
          </div>
        )}
      </div>
    </>
  )
})
