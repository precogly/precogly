import { memo, useEffect, useState } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { cn } from '@/lib/utils'
import { InlineEditableLabel } from './InlineEditableLabel'
import type { HumanActorNodeData } from '../../types'
import { useTechnologyInfo } from '../../api/component-library'

type HumanActorNodeType = Node<HumanActorNodeData, 'humanActor'>

export const HumanActorNode = memo(function HumanActorNode({
  id,
  data,
  selected,
}: NodeProps<HumanActorNodeType>) {
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
          'flex flex-col items-center transition-all',
          technologyIcon
            ? cn('p-1', selected && 'shadow-lg')
            : cn(
                'p-3 rounded-lg bg-green-50 border-2 min-w-[80px]',
                selected ? 'border-green-500 shadow-md' : 'border-green-200'
              ),
          isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2',
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
            {/* Stick figure */}
            <div className="flex flex-col items-center mb-2">
              <div className="w-5 h-5 rounded-full border-2 border-green-600 bg-green-100" />
              <div className="w-0.5 h-4 bg-green-600" />
              <div className="relative -mt-3">
                <div className="absolute w-6 h-0.5 bg-green-600 -left-3" />
              </div>
              <div className="flex mt-1">
                <div className="w-0.5 h-4 bg-green-600 rotate-[20deg] origin-top" />
                <div className="w-0.5 h-4 bg-green-600 -rotate-[20deg] origin-top -ml-0.5" />
              </div>
            </div>
            <InlineEditableLabel
              nodeId={id}
              label={data.label}
              isEditing={data.isInlineEditing}
              className="font-medium text-sm text-green-900 text-center"
              inputClassName="text-sm text-green-900 text-center w-full"
            />
          </>
        )}
      </div>
    </>
  )
})
