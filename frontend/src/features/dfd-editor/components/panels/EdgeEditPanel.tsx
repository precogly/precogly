import { memo, useState, useMemo } from 'react'
import { useReactFlow } from '@xyflow/react'
import { X, Trash2, ArrowRight, ArrowLeftRight, Database, Link, Lock, LockOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Separator } from '@/components/ui/separator'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { useDataAssets } from '@/features/threat-models/api/data-assets'
import {
  useDataFlowAssets,
  useCreateDataFlowAsset,
  useUpdateDataFlowAsset,
  useDeleteDataFlowAsset,
} from '@/features/threat-models/api/data-flow-assets'
import type {
  DataFlowEdge,
  Protocol,
  DiagramNode,
  TrustZoneNodeData,
  TrustBoundaryEdgeData,
} from '../../types'
import { PROTOCOLS, getZoneColorConfig } from '../../types'
import { DATA_SENSITIVITY_TAG_CONFIG } from '@/types/domain'

const PROTECTION_METHODS = [
  { value: 'none', label: 'None' },
  { value: 'encrypted', label: 'Encrypted' },
  { value: 'masked', label: 'Masked' },
  { value: 'tokenized', label: 'Tokenized' },
  { value: 'hashed', label: 'Hashed' },
] as const

/**
 * Data Assets section for data flow edges
 */
function DataFlowDataAssetsSection({
  dataFlowId,
  threatModelId,
}: {
  dataFlowId: number | undefined
  threatModelId: string | undefined
}) {
  const [linkingAsset, setLinkingAsset] = useState(false)
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')

  const { data: flowDataAssets = [] } = useDataFlowAssets(dataFlowId)
  const { data: allDataAssets = [] } = useDataAssets(threatModelId)
  const createMutation = useCreateDataFlowAsset()
  const updateMutation = useUpdateDataFlowAsset()
  const deleteMutation = useDeleteDataFlowAsset()

  if (!dataFlowId) return null

  // Filter out already-linked data assets
  const linkedAssetIds = new Set(flowDataAssets.map((fda) => fda.dataAsset))
  const availableAssets = allDataAssets.filter((asset) => !linkedAssetIds.has(asset.id))

  const handleLinkAsset = () => {
    if (!selectedAssetId) return
    createMutation.mutate(
      {
        dataFlow: dataFlowId,
        dataAsset: parseInt(selectedAssetId, 10),
        protectionMethod: 'none',
      },
      {
        onSuccess: () => {
          setSelectedAssetId('')
          setLinkingAsset(false)
        },
      }
    )
  }

  return (
    <>
      <Separator />
      <div className="space-y-2">
        <Label className="flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5 text-purple-600" />
          Data Assets
          {flowDataAssets.length > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              {flowDataAssets.length}
            </Badge>
          )}
        </Label>

        {/* Linked assets list */}
        {flowDataAssets.length > 0 && (
          <div className="space-y-1.5">
            {flowDataAssets.map((fda) => (
              <div
                key={fda.id}
                className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{fda.dataAssetName}</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Select
                      value={fda.protectionMethod}
                      onValueChange={(value) =>
                        updateMutation.mutate({
                          id: fda.id,
                          data: { protectionMethod: value as typeof fda.protectionMethod },
                        })
                      }
                    >
                      <SelectTrigger className="h-5 w-24 text-[10px] px-1.5">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {PROTECTION_METHODS.map((method) => (
                          <SelectItem key={method.value} value={method.value}>
                            {method.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {fda.protectionMethod === 'encrypted' ? (
                    <Lock className="h-3 w-3 text-green-600" />
                  ) : (
                    <LockOpen className="h-3 w-3 text-muted-foreground" />
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-muted-foreground hover:text-destructive"
                    onClick={() => deleteMutation.mutate(fda.id)}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Link Asset UI */}
        {linkingAsset ? (
          <div className="space-y-2">
            <Select value={selectedAssetId} onValueChange={setSelectedAssetId}>
              <SelectTrigger className="h-8 text-sm">
                <SelectValue placeholder="Select a data asset..." />
              </SelectTrigger>
              <SelectContent>
                {availableAssets.length === 0 ? (
                  <div className="px-2 py-1.5 text-xs text-muted-foreground">
                    No available assets
                  </div>
                ) : (
                  availableAssets.map((asset) => (
                    <SelectItem key={asset.id} value={String(asset.id)}>
                      {asset.name}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            <div className="flex gap-1.5">
              <Button
                size="sm"
                className="h-7 text-xs flex-1"
                disabled={!selectedAssetId || createMutation.isPending}
                onClick={handleLinkAsset}
              >
                Link
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs"
                onClick={() => {
                  setLinkingAsset(false)
                  setSelectedAssetId('')
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1 w-full"
            onClick={() => setLinkingAsset(true)}
          >
            <Link className="h-3 w-3" />
            Link Asset
          </Button>
        )}
      </div>
    </>
  )
}

interface EdgeEditPanelProps {
  edge: DataFlowEdge
  onClose: () => void
  threatModelId?: string
}

export const EdgeEditPanel = memo(function EdgeEditPanel({
  edge,
  onClose,
  threatModelId,
}: EdgeEditPanelProps) {
  const { setEdges, getNodes, getEdges } = useReactFlow()

  const nodes = getNodes()
  const edges = getEdges()
  const sourceNode = nodes.find((n) => n.id === edge.source)
  const targetNode = nodes.find((n) => n.id === edge.target)

  const dataflowId = edge.data?.dataflowId as number | undefined

  const dataClassificationOptions = useMemo(
    () =>
      Object.entries(DATA_SENSITIVITY_TAG_CONFIG).map(([value, config]) => ({
        value,
        label: config.label,
        description: config.description,
      })),
    []
  )

  const updateEdgeData = (updates: Partial<DataFlowEdge['data']>) => {
    setEdges((edges) =>
      edges.map((e) =>
        e.id === edge.id ? { ...e, data: { ...e.data, ...updates } } : e
      )
    )
  }

  const handleDelete = () => {
    setEdges((edges) => edges.filter((e) => e.id !== edge.id))
    onClose()
  }

  const handleReverseDirection = () => {
    setEdges((edges) =>
      edges.map((e) =>
        e.id === edge.id
          ? { ...e, source: edge.target, target: edge.source }
          : e
      )
    )
  }

  return (
    <div className="w-80 bg-background border-l h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2">
          <ArrowRight className="h-5 w-5 text-gray-600" />
          <span className="font-medium">Data Flow</span>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Connection info */}
        <div className="p-3 bg-muted rounded-lg space-y-1 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">From:</span>
            <span className="font-medium">
              {String(sourceNode?.data?.label || edge.source)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">To:</span>
            <span className="font-medium">
              {String(targetNode?.data?.label || edge.target)}
            </span>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          className="w-full"
          onClick={handleReverseDirection}
        >
          <ArrowLeftRight className="h-4 w-4 mr-2" />
          Reverse Direction
        </Button>

        <Separator />

        {/* Label */}
        <div className="space-y-2">
          <Label htmlFor="edge-label">Label</Label>
          <Input
            id="edge-label"
            value={edge.data?.label || ''}
            onChange={(e) => updateEdgeData({ label: e.target.value })}
            placeholder="e.g., User credentials, API request..."
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="edge-description">Description</Label>
          <Textarea
            id="edge-description"
            value={edge.data?.description || ''}
            onChange={(e) => updateEdgeData({ description: e.target.value })}
            placeholder="Describe this data flow..."
            rows={3}
          />
        </div>

        {/* Protocol */}
        <div className="space-y-2">
          <Label htmlFor="edge-protocol">Protocol</Label>
          <Select
            value={edge.data?.protocol || ''}
            onValueChange={(value) => updateEdgeData({ protocol: value as Protocol })}
          >
            <SelectTrigger id="edge-protocol">
              <SelectValue placeholder="Select protocol..." />
            </SelectTrigger>
            <SelectContent>
              {PROTOCOLS.map((protocol) => (
                <SelectItem key={protocol} value={protocol}>
                  {protocol}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {/* Data Classification */}
        <div className="space-y-2">
          <Label>Data Classification</Label>
          <MultiSelectCombobox
            options={dataClassificationOptions}
            selected={edge.data?.dataClassification || []}
            onChange={(tags) => updateEdgeData({ dataClassification: tags })}
            placeholder="Select or add tags..."
            searchPlaceholder="Search or type custom..."
            allowCustom
          />
        </div>

        <Separator />

        {/* Security */}
        <div className="space-y-3">
          <Label>Security</Label>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="edge-encrypted"
              checked={edge.data?.encrypted || false}
              onCheckedChange={(checked) =>
                updateEdgeData({ encrypted: checked as boolean })
              }
            />
            <Label
              htmlFor="edge-encrypted"
              className="text-sm font-normal cursor-pointer"
            >
              Encryption in Transit
            </Label>
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="edge-authenticated"
              checked={edge.data?.authenticated || false}
              onCheckedChange={(checked) =>
                updateEdgeData({ authenticated: checked as boolean })
              }
            />
            <Label
              htmlFor="edge-authenticated"
              className="text-sm font-normal cursor-pointer"
            >
              Authentication Required
            </Label>
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="edge-sensitive-data"
              checked={edge.data?.hasSensitiveData || false}
              onCheckedChange={(checked) =>
                updateEdgeData({ hasSensitiveData: checked as boolean })
              }
            />
            <Label
              htmlFor="edge-sensitive-data"
              className="text-sm font-normal cursor-pointer"
            >
              Contains Sensitive Data
            </Label>
          </div>
        </div>

        {/* Data Flow Assets - only visible when edge has been synced to backend */}
        {dataflowId && (
          <DataFlowDataAssetsSection
            dataFlowId={dataflowId}
            threatModelId={threatModelId}
          />
        )}

        <Separator />

        {/* Zone Crossing */}
        {(() => {
          const trustZones = (nodes as DiagramNode[]).filter(
            (n) => n.type === 'trustZone'
          )
          if (trustZones.length === 0) return null

          return (
            <div className="space-y-2">
              <Label htmlFor="edge-zone">Crosses Zone</Label>
              <Select
                value={edge.data?.crossesZoneId || 'none'}
                onValueChange={(value) => {
                  if (value === 'none') {
                    updateEdgeData({
                      crossesZoneId: undefined,
                      crossesZoneLabel: undefined,
                      crossesZoneTrustLevel: undefined,
                      crossesZoneColor: undefined,
                    })
                  } else {
                    const selectedZoneNode = trustZones.find((b) => b.id === value)
                    const selectedData = selectedZoneNode?.data as TrustZoneNodeData | undefined
                    updateEdgeData({
                      crossesZoneId: value,
                      crossesZoneLabel: selectedData?.label ? String(selectedData.label) : undefined,
                      crossesZoneTrustLevel: selectedData?.trustLevel,
                      crossesZoneColor: selectedData?.zoneColor,
                    })
                  }
                }}
              >
                <SelectTrigger id="edge-zone">
                  <SelectValue placeholder="Select zone..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">
                    <span className="text-muted-foreground">None</span>
                  </SelectItem>
                  {trustZones.map((boundary) => {
                    const data = boundary.data as TrustZoneNodeData
                    const config = getZoneColorConfig(data.zoneColor)
                    return (
                      <SelectItem key={boundary.id} value={boundary.id}>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: config.borderColor }}
                          />
                          <span>{String(boundary.data.label)}</span>
                          <span className="text-xs text-muted-foreground">
                            (TL: {data.trustLevel ?? 75})
                          </span>
                        </div>
                      </SelectItem>
                    )
                  })}
                </SelectContent>
              </Select>
            </div>
          )
        })()}

        {/* Boundary Crossings (auto-detected, read-only display) */}
        {edge.data?.crossesBoundaryIds && edge.data.crossesBoundaryIds.length > 0 && (
          <>
            <Separator />
            <div className="space-y-2">
              <Label>Crosses Boundaries</Label>
              <div className="flex flex-col gap-2">
                {edge.data.crossesBoundaryIds.map((boundaryId) => {
                  // Find boundary edge - try trustBoundaryId (camelCase from backend sync) first
                  let boundaryEdge = edges.find(
                    (e) =>
                      e.type === 'trustBoundary' &&
                      e.data?.trustBoundaryId === boundaryId
                  )

                  // Fallback: try snake_case trust_boundary_id
                  if (!boundaryEdge) {
                    boundaryEdge = edges.find(
                      (e) =>
                        e.type === 'trustBoundary' &&
                        e.data?.trust_boundary_id === boundaryId
                    )
                  }

                  // Fallback: try exact edge ID match (boundary-{id})
                  if (!boundaryEdge) {
                    boundaryEdge = edges.find(
                      (e) =>
                        e.type === 'trustBoundary' &&
                        e.id === `boundary-${boundaryId}`
                    )
                  }

                  const boundaryData = boundaryEdge?.data as TrustBoundaryEdgeData | undefined

                  // Compute display ID from boundary's position in edges list (1-based)
                  // This ensures correct numbering even after reload when boundaryDisplayId is not persisted
                  const allBoundaryEdges = edges.filter((e) => e.type === 'trustBoundary')
                  const boundaryIndexInList = allBoundaryEdges.findIndex((e) => e.id === boundaryEdge?.id)
                  const displayId = boundaryIndexInList >= 0 ? boundaryIndexInList + 1 : boundaryId

                  return (
                    <div
                      key={boundaryId}
                      className="p-2 rounded-md bg-amber-50 border border-amber-200 space-y-1"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-amber-700">⚠️</span>
                        <span className="font-medium text-amber-800">
                          {boundaryData?.label || `Boundary ${displayId}`}
                        </span>
                      </div>
                      {boundaryData?.accessControlMethods && boundaryData.accessControlMethods.length > 0 && (
                        <div className="text-xs text-amber-700">
                          <span className="font-medium">Access Control:</span>{' '}
                          {boundaryData.accessControlMethods.join(', ')}
                        </div>
                      )}
                      {boundaryData?.authenticationMethods && boundaryData.authenticationMethods.length > 0 && (
                        <div className="text-xs text-amber-700">
                          <span className="font-medium">Auth:</span>{' '}
                          {boundaryData.authenticationMethods.join(', ')}
                        </div>
                      )}
                      {!boundaryData?.accessControlMethods?.length && !boundaryData?.authenticationMethods?.length && (
                        <div className="text-xs text-amber-600">
                          No security controls configured
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
              <p className="text-xs text-muted-foreground">
                Boundary crossings are auto-detected based on source and target component zones.
              </p>
            </div>
          </>
        )}

        {/* Edge info */}
        <Separator />

        <div className="space-y-1 text-xs text-muted-foreground">
          <div>ID: {edge.id}</div>
          <div>Type: {edge.type}</div>
        </div>
      </div>

      {/* Footer with delete */}
      <div className="p-4 border-t">
        <Button
          variant="destructive"
          className="w-full"
          onClick={handleDelete}
        >
          <Trash2 className="h-4 w-4 mr-2" />
          Delete Data Flow
        </Button>
      </div>
    </div>
  )
})
