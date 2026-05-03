import { memo, useEffect, useState } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { cn } from '@/lib/utils'
import type { HumanActorNodeData } from '../../types'
import { NodeThreatBadge } from './NodeThreatBadge'

type HumanActorNodeType = Node<HumanActorNodeData, 'humanActor'>

export const HumanActorNode = memo(function HumanActorNode({
  id,
  data,
  selected,
}: NodeProps<HumanActorNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
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
      {/* Handles on all 4 sides for flexible edge routing */}
      {/* Top */}
      <Handle id="top-target" type="target" position={Position.Top} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="top-source" type="source" position={Position.Top} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Right */}
      <Handle id="right-target" type="target" position={Position.Right} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="right-source" type="source" position={Position.Right} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Bottom */}
      <Handle id="bottom-target" type="target" position={Position.Bottom} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="bottom-source" type="source" position={Position.Bottom} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Left */}
      <Handle id="left-target" type="target" position={Position.Left} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="left-source" type="source" position={Position.Left} className="!bg-green-500 !w-2 !h-2 !min-w-0 !min-h-0" />

      <div
        className={cn(
          'flex flex-col items-center p-3 rounded-lg bg-green-50 border-2 min-w-[80px] transition-all',
          selected ? 'border-green-500 shadow-md' : 'border-green-200',
          isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2',
          showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
        )}
      >
        {/* Stick figure */}
        <div className="flex flex-col items-center mb-2">
          {/* Head */}
          <div className="w-5 h-5 rounded-full border-2 border-green-600 bg-green-100" />
          {/* Body */}
          <div className="w-0.5 h-4 bg-green-600" />
          {/* Arms */}
          <div className="relative -mt-3">
            <div className="absolute w-6 h-0.5 bg-green-600 -left-3" />
          </div>
          {/* Legs */}
          <div className="flex mt-1">
            <div className="w-0.5 h-4 bg-green-600 rotate-[20deg] origin-top" />
            <div className="w-0.5 h-4 bg-green-600 -rotate-[20deg] origin-top -ml-0.5" />
          </div>
        </div>

        {/* Label */}
        <span className="font-medium text-sm text-green-900 text-center">
          {data.label}
        </span>
        <NodeThreatBadge nodeId={id} className="mt-1 text-center" />
      </div>
    </>
  )
})
