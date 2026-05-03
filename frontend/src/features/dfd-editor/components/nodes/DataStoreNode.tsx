import { memo, useEffect, useState } from 'react'
import { Handle, Position, NodeResizer, type Node, type NodeProps } from '@xyflow/react'
import { Database } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { DataStoreNodeData } from '../../types'
import { DATA_SENSITIVITY_CONFIG } from '../../types'
import { useTechnologyDisplayName } from '../../api/component-library'
import { NodeThreatBadge } from './NodeThreatBadge'

type DataStoreNodeType = Node<DataStoreNodeData, 'datastore'>

export const DataStoreNode = memo(function DataStoreNode({
  id,
  data,
  selected,
}: NodeProps<DataStoreNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const technologyDisplayName = useTechnologyDisplayName(data.technology)
  const [showLockAnimation, setShowLockAnimation] = useState(false)
  // Trigger lock animation when lockAnimationKey changes (new timestamp = new animation)
  useEffect(() => {
    if (data.lockAnimationKey) {
      setShowLockAnimation(true)
      const timer = setTimeout(() => setShowLockAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.lockAnimationKey])

  return (
    <>
      <NodeResizer
        minWidth={120}
        minHeight={50}
        isVisible={selected}
        lineClassName="!border-solid"
        handleClassName="!w-2 !h-2 !rounded-sm"
        lineStyle={{ borderColor: '#a855f7' }}
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
          'w-full h-full relative min-w-[120px] transition-all',
          isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2 rounded-lg',
          showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2 rounded-lg'
        )}
      >
        {/* Cylinder shape using CSS */}
        <div
          className={cn(
            'w-full h-full relative bg-purple-50 border-2 rounded-lg overflow-hidden flex flex-col',
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
                <span className="font-medium text-sm text-purple-900 truncate">
                  {data.label}
                </span>
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
            <NodeThreatBadge nodeId={id} className="mt-1.5 text-center" />
          </div>

          {/* Bottom ellipse */}
          <div className="h-3 bg-purple-100 border-t border-purple-200 rounded-b-lg flex-shrink-0" />
        </div>
      </div>
    </>
  )
})
