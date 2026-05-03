import { memo, useEffect, useState } from 'react'
import { Handle, Position, NodeResizer, type Node, type NodeProps } from '@xyflow/react'
import { Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { TrustZoneNodeData } from '../../types'
import { getZoneColorConfig } from '../../types'
import { NodeThreatBadge } from './NodeThreatBadge'

type TrustZoneNodeType = Node<TrustZoneNodeData, 'trustZone'>

export const TrustZoneNode = memo(function TrustZoneNode({
  id,
  data,
  selected,
}: NodeProps<TrustZoneNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const [showLockAnimation, setShowLockAnimation] = useState(false)
  const trustLevel = data.trustLevel ?? 75
  const { color: displayColor, borderColor: displayBorderColor } = getZoneColorConfig(data.zoneColor)

  // Trigger lock animation when receiveChildAnimationKey changes (new timestamp = new animation)
  useEffect(() => {
    if (data.receiveChildAnimationKey) {
      setShowLockAnimation(true)
      const timer = setTimeout(() => setShowLockAnimation(false), 500)
      return () => clearTimeout(timer)
    }
  }, [data.receiveChildAnimationKey])

  return (
    <>
      {/* Resizer for adjusting zone size */}
      <NodeResizer
        minWidth={200}
        minHeight={150}
        isVisible={selected}
        lineClassName="!border-dashed"
        handleClassName="!w-2 !h-2 !rounded-sm"
        lineStyle={{ borderColor: displayBorderColor }}
        handleStyle={{ backgroundColor: displayBorderColor, borderColor: displayBorderColor }}
      />

      {/* Handles for connections */}
      <Handle type="target" position={Position.Top} className="!bg-gray-400" />
      <Handle type="target" position={Position.Left} className="!bg-gray-400" />
      <Handle type="source" position={Position.Bottom} className="!bg-gray-400" />
      <Handle type="source" position={Position.Right} className="!bg-gray-400" />

      {/* Trust zone - dashed border, container style */}
      <div
        className={cn(
          'w-full h-full rounded-lg border-2 border-dashed transition-all',
          isNewlyInserted && 'ring-2 ring-green-400 ring-offset-2',
          showLockAnimation && 'animate-lock-pulse ring-2 ring-orange-400 ring-offset-2'
        )}
        style={{
          backgroundColor: displayColor,
          borderColor: displayBorderColor,
        }}
      >
        {/* Label badge at top-left */}
        <div
          className="absolute -top-3 left-3 px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1"
          style={{
            backgroundColor: displayBorderColor,
            color: 'white',
          }}
        >
          <Shield className="h-3 w-3" />
          {data.label}
        </div>

        {/* Trust level indicator */}
        <div
          className="absolute -top-3 right-3 px-2 py-0.5 rounded text-xs"
          style={{
            backgroundColor: 'white',
            color: displayBorderColor,
            border: `1px solid ${displayBorderColor}`,
          }}
        >
          TL: {trustLevel}
        </div>

        <NodeThreatBadge nodeId={id} className="absolute bottom-1 right-3" />
      </div>
    </>
  )
})
