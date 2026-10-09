import { memo, useEffect, useState } from 'react'
import { Handle, Position, NodeResizer, type Node, type NodeProps } from '@xyflow/react'
import { Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ZONE_TYPES } from '@/types/domain'
import { InlineEditableLabel } from './InlineEditableLabel'
import type { TrustZoneNodeData } from '../../types'
import { getZoneColorConfig } from '../../types'
import { getZoneType } from '../../lib/canvas-defaults'
import { getDisplayedTrustLevel } from '../../lib/zone-trust-level'

type TrustZoneNodeType = Node<TrustZoneNodeData, 'trustZone'>

/**
 * A zone on the canvas. The badge at the top left carries the name and the
 * zone type ("Network zone"); the indicator at the top right shows the trust
 * level, and only when one is set (plan 11.2, F13).
 */
export const TrustZoneNode = memo(function TrustZoneNode({
  id,
  data,
  selected,
}: NodeProps<TrustZoneNodeType>) {
  const isNewlyInserted = data.isNewlyInserted
  const [showLockAnimation, setShowLockAnimation] = useState(false)

  const zoneType = getZoneType(data)
  const zoneTypeLabel = ZONE_TYPES.find((entry) => entry.value === zoneType)?.label ?? 'Zone'
  const displayedTrustLevel = getDisplayedTrustLevel(data)
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

      {/* Zone container: dashed border */}
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
        data-zone-type={zoneType}
      >
        {/* Name and type badge at top-left */}
        <div
          className="absolute -top-3 left-3 px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1.5"
          style={{
            backgroundColor: displayBorderColor,
            color: 'white',
          }}
        >
          <Shield className="h-3 w-3" />
          <InlineEditableLabel
            nodeId={id}
            label={data.label}
            isEditing={data.isInlineEditing}
            inputClassName="max-w-[120px] text-white placeholder-white/50"
          />
          <span
            className="rounded bg-white/25 px-1 py-px text-[10px] font-normal uppercase tracking-wide whitespace-nowrap"
            title={zoneTypeLabel}
            data-testid="zone-type-badge"
          >
            {zoneTypeLabel}
          </span>
        </div>

        {/* Trust level indicator, only when a level is set */}
        {displayedTrustLevel !== null && (
          <div
            className="absolute -top-3 right-3 px-2 py-0.5 rounded text-xs"
            style={{
              backgroundColor: 'white',
              color: displayBorderColor,
              border: `1px solid ${displayBorderColor}`,
            }}
            title={`Trust level ${displayedTrustLevel}`}
            data-testid="zone-trust-level"
          >
            TL: {displayedTrustLevel}
          </div>
        )}
      </div>
    </>
  )
})
