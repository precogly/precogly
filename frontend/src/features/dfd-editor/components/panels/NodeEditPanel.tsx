import { memo, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { X, Trash2, Cog, Database, User, Server, Shield, Box, ShieldCheck, ArrowRight, Link, Lock, LockOpen, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Slider } from '@/components/ui/slider'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { TechnologyCombobox } from '../technology-combobox'
import { SuggestionCombobox } from '../suggestion-combobox'
import { NodeThreatSection } from './NodeThreatSection'
import { useThreatModelSystems, useUpdateComponentSystem } from '@/features/threat-models/api/threat-models'
import { useDataAssets } from '@/features/threat-models/api/data-assets'
import {
  useComponentDataAssets,
  useCreateComponentDataAsset,
  useUpdateComponentDataAsset,
  useDeleteComponentDataAsset,
} from '@/features/threat-models/api/component-data-assets'
import type {
  DiagramNode,
  DiagramNodeType,
  DataSensitivity,
} from '../../types'
import {
  DATA_SENSITIVITY_CONFIG,
  ZONE_COLOR_OPTIONS,
  getZoneColorConfig,
  MAX_PROCESS_HIERARCHY_DEPTH,
  getProcessAncestorDepth,
  getProcessDescendantDepth,
} from '../../types'

interface NodeEditPanelProps {
  node: DiagramNode
  onClose: () => void
  threatModelId?: string
}

const nodeTypeConfig: Record<
  DiagramNodeType,
  { label: string; icon: React.ComponentType<{ className?: string }>; color: string }
> = {
  process: { label: 'Process', icon: Cog, color: 'text-blue-600' },
  datastore: { label: 'Data Store', icon: Database, color: 'text-purple-600' },
  humanActor: { label: 'Human Actor', icon: User, color: 'text-green-600' },
  systemActor: { label: 'System Actor', icon: Server, color: 'text-slate-600' },
  trustZone: { label: 'Trust Zone', icon: Shield, color: 'text-orange-600' },
  systemScope: { label: 'System Scope', icon: Box, color: 'text-gray-600' },
}

/**
 * Data Assets section for process/datastore nodes
 */
function DataAssetsSection({
  componentId,
  threatModelId,
}: {
  componentId: number | undefined
  threatModelId: string | undefined
}) {
  const [linkingAsset, setLinkingAsset] = useState(false)
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')

  const { data: componentDataAssets = [] } = useComponentDataAssets(componentId)
  const { data: allDataAssets = [] } = useDataAssets(threatModelId)
  const createMutation = useCreateComponentDataAsset()
  const updateMutation = useUpdateComponentDataAsset()
  const deleteMutation = useDeleteComponentDataAsset()

  if (!componentId) return null

  // Filter out already-linked data assets
  const linkedAssetIds = new Set(componentDataAssets.map((cda) => cda.dataAsset))
  const availableAssets = allDataAssets.filter((asset) => !linkedAssetIds.has(asset.id))

  const handleLinkAsset = () => {
    if (!selectedAssetId) return
    createMutation.mutate(
      {
        component: componentId,
        dataAsset: parseInt(selectedAssetId, 10),
        dataState: 'processed',
        encrypted: false,
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
          {componentDataAssets.length > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              {componentDataAssets.length}
            </Badge>
          )}
        </Label>

        {/* Linked assets list */}
        {componentDataAssets.length > 0 && (
          <div className="space-y-1.5">
            {componentDataAssets.map((cda) => (
              <div
                key={cda.id}
                className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{cda.dataAssetName}</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Badge variant="outline" className="text-[10px] h-4 px-1">
                      {cda.dataState === 'at_rest' ? 'At Rest' : 'Processed'}
                    </Badge>
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  <Checkbox
                    checked={cda.encrypted}
                    onCheckedChange={(checked) =>
                      updateMutation.mutate({
                        id: cda.id,
                        data: { encrypted: !!checked },
                      })
                    }
                    title="Encrypted"
                  />
                  {cda.encrypted ? (
                    <Lock className="h-3 w-3 text-green-600" />
                  ) : (
                    <LockOpen className="h-3 w-3 text-muted-foreground" />
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-muted-foreground hover:text-destructive"
                    onClick={() => deleteMutation.mutate(cda.id)}
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

export const NodeEditPanel = memo(function NodeEditPanel({
  node,
  onClose,
  threatModelId,
}: NodeEditPanelProps) {
  const { setNodes, getNodes, getEdges, setEdges } = useReactFlow()

  // Get linked systems for this threat model
  const { systems: linkedSystems, hasLinkedSystems } = useThreatModelSystems(threatModelId)
  const updateComponentSystemMutation = useUpdateComponentSystem()

  const typeConfig = nodeTypeConfig[node.type as DiagramNodeType]
  const Icon = typeConfig?.icon || Cog

  // Find parent node if exists
  const parentNode = node.parentId
    ? (getNodes() as DiagramNode[]).find((n) => n.id === node.parentId)
    : null

  // Pending technology change awaiting confirmation
  const [pendingTechnology, setPendingTechnology] = useState<string | null>(null)

  const updateNodeData = (updates: Partial<DiagramNode['data']>) => {
    setNodes((nodes) =>
      nodes.map((n) =>
        n.id === node.id ? { ...n, data: { ...n.data, ...updates } } : n
      )
    )
  }

  const handleTechnologyChange = (newValue: string) => {
    const currentTechnology = (node.data as { technology?: string }).technology
    const componentId = (node.data as { componentId?: number }).componentId

    // Show confirmation only when: component is synced, has an existing technology, and it's changing
    if (componentId && currentTechnology && newValue !== currentTechnology) {
      setPendingTechnology(newValue)
    } else {
      updateNodeData({ technology: newValue })
    }
  }

  const confirmTechnologyChange = () => {
    if (pendingTechnology !== null) {
      updateNodeData({ technology: pendingTechnology })
      setPendingTechnology(null)
    }
  }

  const handleDelete = () => {
    const nodes = getNodes() as DiagramNode[]

    // For container nodes (boundaries or process containers), convert children to root nodes
    const hasChildren = nodes.some((n) => n.parentId === node.id)
    if (node.type === 'trustZone' || node.type === 'systemScope' || hasChildren) {
      const boundaryPos = node.position
      const updatedNodes = nodes
        .filter((n) => n.id !== node.id)
        .map((n) => {
          if (n.parentId === node.id) {
            return {
              ...n,
              parentId: undefined,
              position: {
                x: n.position.x + boundaryPos.x,
                y: n.position.y + boundaryPos.y,
              },
            }
          }
          return n
        })
      setNodes(updatedNodes)
    } else {
      setNodes((nodes) => nodes.filter((n) => n.id !== node.id))
    }

    // Remove connected edges
    setEdges((edges) =>
      edges.filter((e) => e.source !== node.id && e.target !== node.id)
    )

    onClose()
  }

  return (
    <div className="w-80 bg-background border-l h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2">
          <Icon className={`h-5 w-5 ${typeConfig?.color}`} />
          <span className="font-medium">{typeConfig?.label || 'Node'}</span>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Common fields */}
        <div className="space-y-2">
          <Label htmlFor="node-label">Name</Label>
          <Input
            id="node-label"
            value={node.data.label || ''}
            onChange={(e) => updateNodeData({ label: e.target.value })}
            placeholder={node.type === 'trustZone' ? 'e.g., Production VPC, DMZ...' : 'Enter name...'}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="node-description">Description</Label>
          <Textarea
            id="node-description"
            value={node.data.description || ''}
            onChange={(e) => updateNodeData({ description: e.target.value })}
            placeholder="Enter description..."
            rows={3}
          />
        </div>

        <Separator />

        {/* Type-specific fields */}
        {(node.type === 'process' || node.type === 'datastore') && (
          <>
            <div className="space-y-2">
              <Label>Technology</Label>
              <TechnologyCombobox
                value={(node.data as { technology?: string }).technology || ''}
                onChange={handleTechnologyChange}
                filterNodeType={node.type as 'process' | 'datastore'}
                placeholder={
                  node.type === 'datastore'
                    ? 'Select storage/database...'
                    : 'Select compute/backend...'
                }
              />
            </div>

            {node.type === 'datastore' && (
              <div className="space-y-2">
                <Label htmlFor="node-storeType">Store Type</Label>
                <Select
                  value={(node.data as { dataStoreType?: string }).dataStoreType || ''}
                  onValueChange={(value) => updateNodeData({ dataStoreType: value })}
                >
                  <SelectTrigger id="node-storeType">
                    <SelectValue placeholder="Select store type..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sql">SQL</SelectItem>
                    <SelectItem value="key_value">Key-Value</SelectItem>
                    <SelectItem value="document">Document</SelectItem>
                    <SelectItem value="object">Object</SelectItem>
                    <SelectItem value="graph">Graph</SelectItem>
                    <SelectItem value="time_series">Time Series</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="node-sensitivity">Data Sensitivity</Label>
              <Select
                value={(node.data as { dataSensitivity?: DataSensitivity }).dataSensitivity || ''}
                onValueChange={(value) =>
                  updateNodeData({ dataSensitivity: value as DataSensitivity })
                }
              >
                <SelectTrigger id="node-sensitivity">
                  <SelectValue placeholder="Select sensitivity..." />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(DATA_SENSITIVITY_CONFIG).map(([key, config]) => (
                    <SelectItem key={key} value={key}>
                      <div className="flex items-center gap-2">
                        <div
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: config.color }}
                        />
                        {config.label}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Parent Process - only for process nodes */}
            {node.type === 'process' && (
              <div className="space-y-2">
                <Label htmlFor="node-parent-process">Parent Process</Label>
                <Select
                  value={(() => {
                    if (!node.parentId) return 'none'
                    const parent = (getNodes() as DiagramNode[]).find(
                      (n) => n.id === node.parentId
                    )
                    return parent?.type === 'process' ? node.parentId : 'none'
                  })()}
                  onValueChange={(value) => {
                    const newParentId = value === 'none' ? undefined : value
                    const allNodes = getNodes() as DiagramNode[]
                    const nodesMap = new Map(allNodes.map((n) => [n.id, n]))

                    // Calculate absolute position by walking parentId chain
                    const getAbsPos = (nodeId: string) => {
                      const n = nodesMap.get(nodeId)
                      if (!n) return { x: 0, y: 0 }
                      let x = n.position.x
                      let y = n.position.y
                      let pid = n.parentId
                      while (pid) {
                        const p = nodesMap.get(pid)
                        if (!p) break
                        x += p.position.x
                        y += p.position.y
                        pid = p.parentId
                      }
                      return { x, y }
                    }

                    let newPos: { x: number; y: number }

                    if (newParentId) {
                      // Place child at a default offset inside the parent
                      newPos = { x: 20, y: 40 }
                    } else {
                      // Un-nesting: convert relative position back to absolute
                      newPos = getAbsPos(node.id)
                    }

                    setNodes((nodes) =>
                      nodes.map((n) => {
                        if (n.id === node.id) {
                          return {
                            ...n,
                            parentId: newParentId,
                            position: newPos,
                            data: {
                              ...n.data,
                              lockAnimationKey: newParentId
                                ? Date.now() + Math.random()
                                : undefined,
                            },
                          }
                        }
                        // When becoming a parent, ensure it has container dimensions
                        if (newParentId && n.id === newParentId) {
                          const hasStyleSize = n.style?.width && n.style?.height
                          const width = hasStyleSize ? undefined : (n.measured?.width || 350)
                          const height = hasStyleSize ? undefined : (n.measured?.height || 250)
                          return {
                            ...n,
                            ...(!hasStyleSize && {
                              style: {
                                ...n.style,
                                width: Math.max(width!, 350),
                                height: Math.max(height!, 250),
                              },
                            }),
                            data: {
                              ...n.data,
                              receiveChildAnimationKey: Date.now() + Math.random(),
                            },
                          }
                        }
                        return n
                      })
                    )
                  }}
                >
                  <SelectTrigger id="node-parent-process">
                    <SelectValue placeholder="None (top-level)" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None (top-level)</SelectItem>
                    {(() => {
                      const allNodes = getNodes() as DiagramNode[]
                      const nodesMap = new Map(allNodes.map((n) => [n.id, n]))

                      return allNodes
                        .filter((n) => {
                          if (n.id === node.id || n.type !== 'process') return false

                          // Cycle check: candidate must not be a descendant of this node
                          let checkId: string | undefined = n.parentId
                          const visited = new Set<string>()
                          while (checkId) {
                            if (visited.has(checkId)) break
                            visited.add(checkId)
                            if (checkId === node.id) return false
                            checkId = nodesMap.get(checkId)?.parentId
                          }

                          // Depth check
                          const parentProcessDepth =
                            getProcessAncestorDepth(n.id, allNodes) + 1
                          const childProcessDepth = getProcessDescendantDepth(
                            node.id,
                            allNodes
                          )
                          if (
                            parentProcessDepth + 1 + childProcessDepth >
                            MAX_PROCESS_HIERARCHY_DEPTH
                          )
                            return false

                          return true
                        })
                        .map((n) => (
                          <SelectItem key={n.id} value={n.id}>
                            {n.data.label || n.id}
                          </SelectItem>
                        ))
                    })()}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Nest this process inside another process
                </p>
              </div>
            )}

            {/* System Assignment - only shown if threat model has linked systems */}
            {hasLinkedSystems && (node.data as { componentId?: number }).componentId && (
              <div className="space-y-2">
                <Label htmlFor="node-system">System</Label>
                <Select
                  value={(node.data as { orgsystemId?: number }).orgsystemId?.toString() || 'none'}
                  onValueChange={(value) => {
                    const componentId = (node.data as { componentId?: number }).componentId
                    if (componentId) {
                      const orgsystemId = value === 'none' ? null : parseInt(value, 10)
                      updateNodeData({ orgsystemId: orgsystemId ?? undefined })
                      updateComponentSystemMutation.mutate({
                        componentId,
                        orgsystemId,
                      })
                    }
                  }}
                >
                  <SelectTrigger id="node-system">
                    <SelectValue placeholder="Not assigned" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Not assigned</SelectItem>
                    {linkedSystems.map((system) => (
                      <SelectItem key={system.id} value={system.id}>
                        {system.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Assign this component to a linked system
                </p>
              </div>
            )}

            {/* Data Assets - only shown when component has been synced */}
            <DataAssetsSection
              componentId={(node.data as { componentId?: number }).componentId}
              threatModelId={threatModelId}
            />
          </>
        )}

        {node.type === 'humanActor' && (
          <div className="space-y-2">
            <Label>Actor Type</Label>
            <SuggestionCombobox
              value={(node.data as { actorType?: string }).actorType || ''}
              onChange={(value) => updateNodeData({ actorType: value })}
              suggestions={[
                { value: 'user', label: 'User' },
                { value: 'power_user', label: 'Power User' },
                { value: 'administrator', label: 'Administrator' },
                { value: 'engineer', label: 'Engineer' },
                { value: 'third_party', label: 'Third Party' },
                { value: 'customer', label: 'Customer' },
              ]}
              placeholder="Select or type actor type..."
            />
          </div>
        )}

        {node.type === 'trustZone' && (
          <>
            <div className="space-y-3">
              <Label>Trust Level</Label>
              <Slider
                value={[(node.data as { trustLevel?: number }).trustLevel ?? 75]}
                onValueChange={([value]) => updateNodeData({ trustLevel: value })}
                min={0}
                max={100}
                step={1}
                className="w-full"
              />
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>0 — untrusted</span>
                <span className="font-medium text-foreground">
                  {(node.data as { trustLevel?: number }).trustLevel ?? 75}
                </span>
                <span>100 — restricted</span>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Zone Color</Label>
              <Select
                value={(node.data as { zoneColor?: string }).zoneColor || '#22c55e'}
                onValueChange={(value) => updateNodeData({ zoneColor: value })}
              >
                <SelectTrigger className="h-9">
                  <SelectValue>
                    <div className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded-full border"
                        style={{ backgroundColor: getZoneColorConfig((node.data as { zoneColor?: string }).zoneColor).borderColor }}
                      />
                      {ZONE_COLOR_OPTIONS.find(o => o.borderColor === ((node.data as { zoneColor?: string }).zoneColor || '#22c55e'))?.label || 'Green'}
                    </div>
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {ZONE_COLOR_OPTIONS.map((option) => (
                    <SelectItem key={option.borderColor} value={option.borderColor}>
                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full border"
                          style={{ backgroundColor: option.borderColor }}
                        />
                        {option.label}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Technology</Label>
              <TechnologyCombobox
                value={(node.data as { technology?: string }).technology || ''}
                onChange={(value) => updateNodeData({ technology: value })}
                filterNodeType="trustZone"
                placeholder="Select networking/security..."
              />
            </div>

            {/* Trust Boundaries (read-only) */}
            {(() => {
              const allEdges = getEdges()
              const boundaryEdges = allEdges.filter(
                (e) =>
                  e.type === 'trustBoundary' &&
                  (e.source === node.id || e.target === node.id)
              )
              if (boundaryEdges.length === 0) return null
              const allNodes = getNodes()
              return (
                <>
                  <Separator />
                  <div className="space-y-2">
                    <Label className="flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5 text-orange-600" />
                      Trust Boundaries
                    </Label>
                    <div className="space-y-1">
                      {boundaryEdges.map((boundaryEdge) => {
                        const isSource = boundaryEdge.source === node.id
                        const otherNodeId = isSource ? boundaryEdge.target : boundaryEdge.source
                        const otherNode = allNodes.find((n) => n.id === otherNodeId)
                        const otherLabel = otherNode?.data?.label
                          ? String(otherNode.data.label)
                          : otherNodeId
                        return (
                          <div
                            key={boundaryEdge.id}
                            className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm"
                          >
                            <ArrowRight
                              className={`h-3 w-3 text-orange-600 ${isSource ? '' : 'rotate-180'}`}
                            />
                            <span className="text-muted-foreground">
                              {isSource ? 'To' : 'From'}:
                            </span>
                            <span className="font-medium">{otherLabel}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </>
              )
            })()}
          </>
        )}

        {node.type === 'systemActor' && (
          <>
            <div className="space-y-2">
              <Label>System Type</Label>
              <SuggestionCombobox
                value={(node.data as { systemType?: string }).systemType || ''}
                onChange={(value) => updateNodeData({ systemType: value })}
                suggestions={[
                  { value: 'api', label: 'Third-party API' },
                  { value: 'legacy', label: 'Legacy System' },
                  { value: 'partner', label: 'Partner System' },
                  { value: 'third_party', label: 'Third-party Service' },
                  { value: 'saas', label: 'SaaS' },
                  { value: 'other', label: 'Other' },
                ]}
                placeholder="Select or type system type..."
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="node-vendor">Vendor</Label>
              <Input
                id="node-vendor"
                value={(node.data as { vendor?: string }).vendor || ''}
                onChange={(e) => updateNodeData({ vendor: e.target.value })}
                placeholder="e.g., Stripe, Twilio..."
              />
            </div>
          </>
        )}

        {node.type === 'systemScope' && (
          <>
            <div className="space-y-2">
              <Label>Technology</Label>
              <TechnologyCombobox
                value={(node.data as { technology?: string }).technology || ''}
                onChange={(value) => updateNodeData({ technology: value })}
                filterNodeType="systemScope"
                placeholder="Select infrastructure..."
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="node-owner">Owner</Label>
              <Input
                id="node-owner"
                value={(node.data as { owner?: string }).owner || ''}
                onChange={(e) => updateNodeData({ owner: e.target.value })}
                placeholder="Team or person responsible..."
              />
            </div>
          </>
        )}

        {/* Parent info */}
        {parentNode && (
          <>
            <Separator />
            <div className="space-y-2">
              <Label className="text-muted-foreground">Contained In</Label>
              <div className="flex items-center gap-2 p-2 rounded-md bg-muted/50">
                {parentNode.type === 'trustZone' ? (
                  <Shield className="h-4 w-4 text-orange-600" />
                ) : parentNode.type === 'process' ? (
                  <Cog className="h-4 w-4 text-blue-600" />
                ) : (
                  <Box className="h-4 w-4 text-gray-600" />
                )}
                <span className="text-sm font-medium">{parentNode.data.label}</span>
              </div>
            </div>
          </>
        )}

        {/* Threats & Countermeasures — all analyzable node types */}
        {['process', 'datastore', 'humanActor', 'systemActor'].includes(node.type as string) && (
          (node.data as { componentId?: number }).componentId ? (
            <NodeThreatSection
              componentId={(node.data as { componentId?: number }).componentId!}
              componentName={String(node.data.label || '')}
            />
          ) : (
            <>
              <Separator />
              <div className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-xs text-muted-foreground">
                <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
                Save the diagram to enable threat analysis for this component.
              </div>
            </>
          )
        )}

        {/* Node info */}
        <Separator />

        <div className="space-y-1 text-xs text-muted-foreground">
          <div>ID: {node.id}</div>
          <div>Type: {node.type}</div>
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
          Delete Node
        </Button>
      </div>

      {/* Technology change confirmation dialog */}
      <AlertDialog open={pendingTechnology !== null} onOpenChange={(open) => { if (!open) setPendingTechnology(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Change Technology?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This component has already been synced. Changing its technology will
              replace the current component and regenerate all associated threats.
              Any existing threat analysis work (countermeasures, risk ratings) for
              this component will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmTechnologyChange}>
              Change Technology
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
})
