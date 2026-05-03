import { memo, useEffect, useState } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { Server } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { SystemActorNodeData } from '../../types'
import { NodeThreatBadge } from './NodeThreatBadge'

type SystemActorNodeType = Node<SystemActorNodeData, 'systemActor'>

export const SystemActorNode = memo(function SystemActorNode({
  id,
  data,
  selected,
}: NodeProps<SystemActorNodeType>) {
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
      <Handle id="top-target" type="target" position={Position.Top} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="top-source" type="source" position={Position.Top} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Right */}
      <Handle id="right-target" type="target" position={Position.Right} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="right-source" type="source" position={Position.Right} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Bottom */}
      <Handle id="bottom-target" type="target" position={Position.Bottom} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="bottom-source" type="source" position={Position.Bottom} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      {/* Left */}
      <Handle id="left-target" type="target" position={Position.Left} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />
      <Handle id="left-source" type="source" position={Position.Left} className="!bg-slate-500 !w-2 !h-2 !min-w-0 !min-h-0" />

      <div
        className={cn(
          'flex flex-col items-center p-3 bg-slate-50 border-2 min-w-[80px] transition-all',
          // Sharp corners - no rounded class
          selected ? 'border-slate-500 shadow-md' : 'border-slate-400',
          isNewlyInserted && 'ring-2 ring-slate-400 ring-offset-2',
          showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
        )}
      >
        {/* Server icon */}
        <Server className="w-8 h-8 text-slate-600 mb-2" />

        {/* Label */}
        <span className="font-medium text-sm text-slate-900 text-center">
          {data.label}
        </span>
        <NodeThreatBadge nodeId={id} className="mt-1 text-center" />
      </div>
    </>
  )
})
