import { useState } from 'react'
import { Database, ChevronDown, ChevronUp, Lock, LockOpen } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useFlowAssets } from '@/features/threat-models/api/flow-assets'

export function DataFlowAssetsDisplay({
  dataFlowId,
}: {
  dataFlowId: number | undefined
}) {
  const [collapsed, setCollapsed] = useState(false)
  const { data: flowDataAssets = [] } = useFlowAssets(dataFlowId)

  if (!dataFlowId || flowDataAssets.length === 0) return null

  const protectionLabels: Record<string, string> = {
    encrypted: 'Encrypted',
    masked: 'Masked',
    tokenized: 'Tokenized',
    hashed: 'Hashed',
    none: 'None',
  }

  return (
    <div className="ml-6 mt-1 mb-1">
      <button
        className="w-full flex items-center justify-between text-xs"
        onClick={(e) => {
          e.stopPropagation()
          setCollapsed(!collapsed)
        }}
      >
        <div className="flex items-center gap-1.5">
          <Database className="h-3 w-3 text-purple-600" />
          <span className="font-medium text-muted-foreground">Data Assets</span>
          <Badge variant="secondary" className="h-4 px-1 text-[10px]">
            {flowDataAssets.length}
          </Badge>
        </div>
        {collapsed ? (
          <ChevronDown className="h-3 w-3 text-muted-foreground" />
        ) : (
          <ChevronUp className="h-3 w-3 text-muted-foreground" />
        )}
      </button>
      {!collapsed && (
        <div className="mt-1.5 space-y-1">
          {flowDataAssets.map((fda) => (
            <div
              key={fda.id}
              className="flex items-center gap-2 py-1 text-xs"
            >
              {fda.protectionMethod === 'encrypted' ? (
                <Lock className="h-3 w-3 text-green-600 flex-shrink-0" />
              ) : (
                <LockOpen className="h-3 w-3 text-muted-foreground flex-shrink-0" />
              )}
              <span className="truncate flex-1">{fda.dataAssetName}</span>
              <Badge variant="outline" className="text-[10px] h-4 px-1 flex-shrink-0">
                {protectionLabels[fda.protectionMethod] || fda.protectionMethod}
              </Badge>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
