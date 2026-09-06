import { memo, useEffect, useState } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { Server } from 'lucide-react'
import { cn } from '@/lib/utils'
import { InlineEditableLabel } from './InlineEditableLabel'
import type { SystemActorNodeData } from '../../types'
import { useTechnologyInfo } from '../../api/component-library'

type SystemActorNodeType = Node<SystemActorNodeData, 'systemActor'>

export const SystemActorNode = memo(function SystemActorNode({
  id,
  data,
  selected,
}: NodeProps<SystemActorNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const technologySlug = data.technology || (data as Record<string, unknown>).componentRef as string | undefined
  const { iconSvg: technologyIcon } = useTechnologyInfo(technologySlug)
  const [showLockAnimation, setShowLockAnimation] = useState(false)

  useEffect(() => {
    if (data.lockAnimationKey) {
      setShowLockAnimation(true)
      const timer = setTimeout(() => setShowLockAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.lockAnimationKey])

  return (
    <>
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
          'flex flex-col items-center transition-all',
          technologyIcon
            ? cn('p-1', selected && 'shadow-lg')
            : cn(
                'p-3 bg-slate-50 border-2 min-w-[80px]',
                selected ? 'border-slate-500 shadow-md' : 'border-slate-400'
              ),
          isNewlyInserted && 'ring-2 ring-slate-400 ring-offset-2',
          showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
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
          </>
        ) : (
          <>
            <Server className="w-8 h-8 text-slate-600 mb-2" />
            <InlineEditableLabel
              nodeId={id}
              label={data.label}
              isEditing={data.isInlineEditing}
              className="font-medium text-sm text-slate-900 text-center"
              inputClassName="text-sm text-slate-900 text-center w-full"
            />
          </>
        )}
      </div>
    </>
  )
})
