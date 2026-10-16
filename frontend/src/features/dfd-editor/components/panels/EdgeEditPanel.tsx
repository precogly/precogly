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
  useFlowAssets,
  useCreateFlowAsset,
  useUpdateFlowAsset,
  useDeleteFlowAsset,
} from '@/features/threat-models/api/flow-assets'
import type {
  DataFlowEdge,
  Protocol,
  DiagramNode,
  TrustZoneNodeData,
} from '../../types'
import { PROTOCOLS, getZoneColorConfig } from '../../types'
import {
  AUTHENTICATION_TYPES,
  DATA_SENSITIVITY_TAG_CONFIG,
  FLOW_TYPES,
  NO_AUTHENTICATION,
  UNSPECIFIED_AUTHENTICATION,
  isDataLikeFlowType,
  type AuthenticationType,
  type FlowType,
} from '@/types/domain'
import { getAuthentication, getFlowType } from '../../lib/canvas-defaults'
import { normalizeAuthenticationSelection } from '../../lib/authentication-selection'
import { getTrustLevel } from '../../lib/zone-trust-level'
import { useGuestEditor } from '@/features/guest-editor/context/GuestEditorContext'
import { AdvancedSection } from './AdvancedSection'

const PROTECTION_METHODS = [
  { value: 'none', label: 'None' },
  { value: 'encrypted', label: 'Encrypted' },
  { value: 'masked', label: 'Masked' },
  { value: 'tokenized', label: 'Tokenized' },
  { value: 'hashed', label: 'Hashed' },
] as const

/**
 * Data assets carried by the flow. Shown for every flow type (plan F15); the
 * links need the flow's backend row, so an unsaved flow shows a hint instead.
 */
function FlowDataAssetsSection({
  flowId,
  threatModelId,
}: {
  flowId: number | undefined
  threatModelId: string | undefined
}) {
  const [linkingAsset, setLinkingAsset] = useState(false)
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')

  const { data: flowDataAssets = [] } = useFlowAssets(flowId)
  const { data: allDataAssets = [] } = useDataAssets(threatModelId)
  const createMutation = useCreateFlowAsset()
  const updateMutation = useUpdateFlowAsset()
  const deleteMutation = useDeleteFlowAsset()

  // Filter out already-linked data assets
  const linkedAssetIds = new Set(flowDataAssets.map((flowAsset) => flowAsset.dataAsset))
  const availableAssets = allDataAssets.filter((asset) => !linkedAssetIds.has(asset.id))

  const handleLinkAsset = () => {
    if (!selectedAssetId || !flowId) return
    createMutation.mutate(
      {
        flow: flowId,
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
      <div className="space-y-2" data-testid="flow-data-assets">
        <Label className="flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5 text-purple-600" />
          Data Assets
          {flowDataAssets.length > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              {flowDataAssets.length}
            </Badge>
          )}
        </Label>

        {!flowId && (
          <p className="text-xs text-muted-foreground">
            Save the diagram to link data assets to this flow.
          </p>
        )}

        {/* Linked assets list */}
        {flowDataAssets.length > 0 && (
          <div className="space-y-1.5">
            {flowDataAssets.map((flowAsset) => (
              <div
                key={flowAsset.id}
                className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{flowAsset.dataAssetName}</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Select
                      value={flowAsset.protectionMethod}
                      onValueChange={(value) =>
                        updateMutation.mutate({
                          id: flowAsset.id,
                          data: { protectionMethod: value as typeof flowAsset.protectionMethod },
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
                  {flowAsset.protectionMethod === 'encrypted' ? (
                    <Lock className="h-3 w-3 text-green-600" />
                  ) : (
                    <LockOpen className="h-3 w-3 text-muted-foreground" />
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-muted-foreground hover:text-destructive"
                    onClick={() => deleteMutation.mutate(flowAsset.id)}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Link Asset UI */}
        {flowId && (linkingAsset ? (
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
        ))}
      </div>
    </>
  )
}

interface EdgeEditPanelProps {
  edge: DataFlowEdge
  onClose: () => void
  threatModelId?: string
  renderExtra?: React.ReactNode
}

/**
 * The side panel for a flow edge (plan 11.2, 4.6).
 *
 * Core: flow type (first), label, description, protocol and encryption for
 * data-like types only, authentication (the spec list with "Method not
 * specified" and "None" as quick choices), data classification, sensitive
 * data, data assets (every type), the zone whose boundary it crosses.
 * Advanced: port (data-like types only).
 *
 * Canvas keys written: `flowType`, `protocol`, `encrypted`, `port`,
 * `authentication`, `dataClassification`, `hasSensitiveData`, `crossesZone*`.
 */
export const EdgeEditPanel = memo(function EdgeEditPanel({
  edge,
  onClose,
  threatModelId,
  renderExtra,
}: EdgeEditPanelProps) {
  const { setEdges, getNodes } = useReactFlow()
  const guestEditor = useGuestEditor()

  const nodes = getNodes()
  const sourceNode = nodes.find((n) => n.id === edge.source)
  const targetNode = nodes.find((n) => n.id === edge.target)

  const flowId = edge.data?.dataflowId as number | undefined
  const flowType = getFlowType(edge.data)
  const flowTypeLabel = FLOW_TYPES.find((entry) => entry.value === flowType)?.label ?? 'Flow'
  const dataLike = isDataLikeFlowType(flowType)
  const authentication = getAuthentication(edge.data)

  const dataClassificationOptions = useMemo(
    () =>
      Object.entries(DATA_SENSITIVITY_TAG_CONFIG).map(([value, config]) => ({
        value,
        label: config.label,
        description: config.description,
      })),
    []
  )

  const authenticationOptions = useMemo(
    () => AUTHENTICATION_TYPES.map((entry) => ({ value: entry.value, label: entry.label })),
    []
  )

  const updateEdgeData = (updates: Partial<DataFlowEdge['data']>) => {
    setEdges((edges) =>
      edges.map((e) =>
        e.id === edge.id ? { ...e, data: { ...e.data, ...updates } } : e
      )
    )
  }

  const handleFlowTypeChange = (value: string) => {
    const nextType = value as FlowType
    // Protocol, port and encryption mean nothing on a signal or energy flow;
    // the backend drops them too, so clear them when leaving a data-like type.
    if (!isDataLikeFlowType(nextType)) {
      updateEdgeData({ flowType: nextType, protocol: undefined, port: undefined, encrypted: false })
    } else {
      updateEdgeData({ flowType: nextType })
    }
  }

  const handleAuthenticationChange = (selected: string[]) => {
    updateEdgeData({
      authentication: normalizeAuthenticationSelection(authentication, selected) as AuthenticationType[],
    })
  }

  const handleDelete = () => {
    if (guestEditor) {
      for (const threat of guestEditor.getThreatsForTarget(edge.id)) {
        guestEditor.removeThreat(threat.id)
      }
    }
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
    <div className="w-80 bg-background border-l h-full flex flex-col" data-testid="flow-panel">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2 min-w-0">
          <ArrowRight className="h-5 w-5 text-gray-600 shrink-0" />
          <span className="font-medium">Flow</span>
          <Badge variant="outline" className="text-[10px] h-5 px-1.5 truncate" title={flowTypeLabel}>
            {flowTypeLabel}
          </Badge>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Flow type, at the top */}
        <div className="space-y-2">
          <Label htmlFor="edge-flow-type">Type</Label>
          <Select value={flowType} onValueChange={handleFlowTypeChange}>
            <SelectTrigger id="edge-flow-type" data-testid="flow-type-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FLOW_TYPES.map((entry) => (
                <SelectItem key={entry.value} value={entry.value}>
                  {entry.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

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
            placeholder="Describe this flow..."
            rows={3}
          />
        </div>

        {/* Protocol: data-like types only */}
        {dataLike && (
          <div className="space-y-2">
            <Label htmlFor="edge-protocol">Protocol</Label>
            <Select
              value={edge.data?.protocol || ''}
              onValueChange={(value) => updateEdgeData({ protocol: value as Protocol })}
            >
              <SelectTrigger id="edge-protocol" data-testid="flow-protocol-select">
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
        )}

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

          {dataLike && (
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
          )}

          {/* Authentication: the spec list; quick choices for the two placeholders */}
          <div className="space-y-2">
            <Label className="text-sm font-normal">Authentication</Label>
            <MultiSelectCombobox
              options={authenticationOptions}
              selected={authentication}
              onChange={handleAuthenticationChange}
              placeholder="Add a method..."
              searchPlaceholder="Search methods or type a custom name..."
              allowCustom
            />
            <div className="flex flex-wrap gap-1.5">
              <Button
                type="button"
                variant={authentication.includes(UNSPECIFIED_AUTHENTICATION) ? 'secondary' : 'outline'}
                size="sm"
                className="h-6 text-xs"
                onClick={() => updateEdgeData({ authentication: [UNSPECIFIED_AUTHENTICATION] })}
              >
                Authenticated, method not specified
              </Button>
              <Button
                type="button"
                variant={authentication.includes(NO_AUTHENTICATION) ? 'secondary' : 'outline'}
                size="sm"
                className="h-6 text-xs"
                onClick={() => updateEdgeData({ authentication: [NO_AUTHENTICATION] })}
              >
                None
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Empty means not recorded.
            </p>
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

        {/* Data assets: every flow type; links need the backend row (signed-in only) */}
        {threatModelId && (
          <FlowDataAssetsSection flowId={flowId} threatModelId={threatModelId} />
        )}

        <Separator />

        {/* Crossed boundary: the zone whose boundary this flow crosses */}
        {(() => {
          const zones = (nodes as DiagramNode[]).filter((n) => n.type === 'trustZone')
          if (zones.length === 0) return null

          return (
            <div className="space-y-2">
              <Label htmlFor="edge-zone">Crosses boundary</Label>
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
                    const selectedZoneNode = zones.find((zone) => zone.id === value)
                    const selectedData = selectedZoneNode?.data as TrustZoneNodeData | undefined
                    updateEdgeData({
                      crossesZoneId: value,
                      crossesZoneLabel: selectedData?.label ? String(selectedData.label) : undefined,
                      crossesZoneTrustLevel: getTrustLevel(selectedData) ?? undefined,
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
                  {zones.map((zone) => {
                    const data = zone.data as TrustZoneNodeData
                    const config = getZoneColorConfig(data.zoneColor)
                    const trustLevel = getTrustLevel(data)
                    return (
                      <SelectItem key={zone.id} value={zone.id}>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: config.borderColor }}
                          />
                          <span>{String(zone.data.label)}</span>
                          {trustLevel !== null && (
                            <span className="text-xs text-muted-foreground">(TL: {trustLevel})</span>
                          )}
                        </div>
                      </SelectItem>
                    )
                  })}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                The zone whose boundary this flow crosses. Whether it crosses one is worked out from the boundaries when the diagram is saved.
              </p>
            </div>
          )
        })()}

        {/* Advanced: port, data-like types only */}
        {dataLike && (
          <>
            <Separator />
            <AdvancedSection>
              <div className="space-y-1">
                <Label htmlFor="edge-port" className="text-sm font-normal">
                  Port
                </Label>
                <Input
                  id="edge-port"
                  type="number"
                  min={0}
                  max={65535}
                  value={edge.data?.port ?? ''}
                  onChange={(e) =>
                    updateEdgeData({ port: e.target.value ? parseInt(e.target.value, 10) : undefined })
                  }
                  placeholder="e.g., 443"
                />
              </div>
            </AdvancedSection>
          </>
        )}

        {/* Extra content (e.g. guest threat section) */}
        {renderExtra && (
          <>
            <Separator />
            {renderExtra}
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
          Delete Flow
        </Button>
      </div>
    </div>
  )
})
