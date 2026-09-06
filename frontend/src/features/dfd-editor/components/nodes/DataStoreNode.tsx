import { memo, useEffect, useState } from 'react'
import { Handle, Position, NodeResizer, type Node, type NodeProps } from '@xyflow/react'
import { Database } from 'lucide-react'
import { cn } from '@/lib/utils'
import { InlineEditableLabel } from './InlineEditableLabel'
import type { DataStoreNodeData } from '../../types'
import { DATA_SENSITIVITY_CONFIG } from '../../types'
import { useTechnologyInfo } from '../../api/component-library'
import { useDFDNotation } from '../../context/DFDNotationContext'

type DataStoreNodeType = Node<DataStoreNodeData, 'datastore'>

export const DataStoreNode = memo(function DataStoreNode({
  id,
  data,
  selected,
}: NodeProps<DataStoreNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const technologySlug = data.technology || (data as Record<string, unknown>).componentRef as string | undefined
  const { displayName: technologyDisplayName, iconSvg: technologyIcon } = useTechnologyInfo(technologySlug)
  const [showLockAnimation, setShowLockAnimation] = useState(false)
  const { notationStyle } = useDFDNotation()

  // Trigger lock animation when lockAnimationKey changes (new timestamp = new animation)
  useEffect(() => {
    if (data.lockAnimationKey) {
      setShowLockAnimation(true)
      const timer = setTimeout(() => setShowLockAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.lockAnimationKey])

  const isYourdon = notationStyle === 'yourdon'

  return (
    <>
      <NodeResizer
        minWidth={isYourdon ? 80 : 120}
        minHeight={isYourdon ? 30 : 50}
        isVisible={selected}
        lineClassName={isYourdon ? '!border-none' : '!border-solid'}
        handleClassName="!w-2 !h-2 !rounded-sm"
        lineStyle={isYourdon ? { borderColor: 'transparent' } : { borderColor: '#a855f7' }}
        handleStyle={{ backgroundColor: '#a855f7', borderColor: '#a855f7' }}
      />
      {/* Handles on all 4 sides for flexible edge routing */}
      {/* Top */}
      <Handle id="top-target" type="target" position={Position.Top} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="top-source" type="source" position={Position.Top} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Right */}
      <Handle id="right-target" type="target" position={Position.Right} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="right-source" type="source" position={Position.Right} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Bottom */}
      <Handle id="bottom-target" type="target" position={Position.Bottom} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="bottom-source" type="source" position={Position.Bottom} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Left */}
      <Handle id="left-target" type="target" position={Position.Left} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="left-source" type="source" position={Position.Left} className="!bg-purple-500 !w-2 !h-2 !min-w-0 !min-h-0" />

      <div
        className={cn(
          'w-full h-full relative transition-all',
          technologyIcon
            ? cn(
                'flex flex-col items-center justify-center p-1',
                selected && 'shadow-lg',
                showLockAnimation && 'animate-lock-pulse'
              )
            : cn(
                !isYourdon && isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2 rounded-lg',
                !isYourdon && showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2 rounded-lg'
              )
        )}
      >
        {technologyIcon ? (
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
            {data.dataSensitivity && DATA_SENSITIVITY_CONFIG[data.dataSensitivity] && (
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
          /* Yourdon/DeMarco: two parallel horizontal lines */
          <div
            className={cn(
              'w-full min-h-full relative bg-purple-50 flex items-center border-t-2 border-b-2',
              selected ? 'border-purple-500 shadow-md' : 'border-purple-200',
              isNewlyInserted && 'shadow-[0_-2px_0_0_#4ade80,0_2px_0_0_#4ade80]',
              showLockAnimation && 'animate-lock-pulse shadow-[0_-2px_0_0_#fb923c,0_2px_0_0_#fb923c]'
            )}
          >
            <div className="px-3 py-1 flex items-center gap-2 w-full">
              <Database className="h-3.5 w-3.5 text-purple-600 flex-shrink-0" />
              <div className="flex flex-col min-w-0 flex-1">
                <InlineEditableLabel
                  nodeId={id}
                  label={data.label}
                  isEditing={data.isInlineEditing}
                  className="font-medium text-xs text-purple-900 line-clamp-6 break-words"
                  inputClassName="text-xs text-purple-900 w-full"
                />
                {data.technology && (
                  <span className="text-[10px] text-purple-600 truncate">
                    {technologyDisplayName}
                  </span>
                )}
                {data.dataSensitivity && DATA_SENSITIVITY_CONFIG[data.dataSensitivity] && (
                  <span
                    className="text-[10px] px-1 rounded truncate mt-0.5"
                    style={{
                      backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                      color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                    }}
                  >
                    {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
                  </span>
                )}
              </div>
            </div>
          </div>
        ) : (
          /* DFD3: Cylinder shape using CSS */
          <div
            className={cn(
              'w-full min-h-full relative bg-purple-50 border-2 rounded-lg overflow-hidden flex flex-col min-w-[120px]',
              selected ? 'border-purple-500 shadow-md' : 'border-purple-200'
            )}
          >
            {/* Top ellipse */}
            <div className="h-3 bg-purple-100 border-b border-purple-200 rounded-t-lg flex-shrink-0" />

            {/* Body */}
            <div className="px-4 py-3 flex-1">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-purple-600 flex-shrink-0" />
                <div className="flex flex-col min-w-0">
                  <InlineEditableLabel
                    nodeId={id}
                    label={data.label}
                    isEditing={data.isInlineEditing}
                    className="font-medium text-sm text-purple-900 line-clamp-6 break-words"
                    inputClassName="text-sm text-purple-900 w-full"
                  />
                  {data.technology && (
                    <span className="text-xs text-purple-600 truncate">
                      {technologyDisplayName}
                    </span>
                  )}
                </div>
              </div>
              {data.dataSensitivity && DATA_SENSITIVITY_CONFIG[data.dataSensitivity] && (
                <div
                  className="mt-2 text-xs px-1.5 py-0.5 rounded text-center"
                  style={{
                    backgroundColor: `${DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color}20`,
                    color: DATA_SENSITIVITY_CONFIG[data.dataSensitivity].color,
                  }}
                >
                  {DATA_SENSITIVITY_CONFIG[data.dataSensitivity].label}
                </div>
              )}
            </div>

            {/* Bottom ellipse */}
            <div className="h-3 bg-purple-100 border-t border-purple-200 rounded-b-lg flex-shrink-0" />
          </div>
        )}
      </div>
    </>
  )
})
