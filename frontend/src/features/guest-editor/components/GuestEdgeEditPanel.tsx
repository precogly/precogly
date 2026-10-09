import { memo } from 'react'
import { useReactFlow } from '@xyflow/react'
import { X, Trash2, ArrowRight, Lock, LockOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
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
import type { DataFlowEdge, DiagramNode } from '@/features/dfd-editor/types'
import { PROTOCOLS } from '@/features/dfd-editor/types'
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
import { getAuthentication, getFlowType, isAuthenticated } from '@/features/dfd-editor/lib/canvas-defaults'
import { normalizeAuthenticationSelection } from '@/features/dfd-editor/lib/authentication-selection'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GuestThreatSection } from './GuestThreatSection'

interface GuestEdgeEditPanelProps {
  edge: DataFlowEdge
  onClose: () => void
}

/**
 * The guest editor's side panel for a flow (plan 11.9): flow type, protocol,
 * port and encryption for data-like types, the authentication list with the
 * `unspecified` quick choice, data classification and the threat section.
 * Built on the domain lists and the canvas accessors; writes the same canvas
 * keys as the signed-in editor.
 */
export const GuestEdgeEditPanel = memo(function GuestEdgeEditPanel({ edge, onClose }: GuestEdgeEditPanelProps) {
  const { setEdges, getNodes } = useReactFlow()
  const guestEditor = useGuestEditor()

  const nodes = getNodes() as DiagramNode[]
  const sourceNode = nodes.find((node) => node.id === edge.source)
  const targetNode = nodes.find((node) => node.id === edge.target)
  const data = edge.data ?? {}
  const flowType = getFlowType(data)
  const dataLike = isDataLikeFlowType(flowType)
  const authentication = getAuthentication(data)
  const authenticated = isAuthenticated(authentication)

  const updateEdgeData = (updates: Record<string, unknown>) => {
    setEdges((edges) =>
      edges.map((candidate) => (candidate.id === edge.id ? { ...candidate, data: { ...candidate.data, ...updates } } : candidate))
    )
  }

  const handleFlowTypeChange = (value: FlowType) => {
    const updates: Record<string, unknown> = { flowType: value }
    if (!isDataLikeFlowType(value)) {
      updates.protocol = undefined
      updates.port = undefined
      updates.encrypted = false
    }
    updateEdgeData(updates)
  }

  const handleDelete = () => {
    guestEditor?.removeDiagramElements([edge.id])
    setEdges((edges) => edges.filter((candidate) => candidate.id !== edge.id))
    onClose()
  }

  const authenticationOptions = AUTHENTICATION_TYPES.map((entry) => ({ value: entry.value, label: entry.label }))
  const label = typeof data.label === 'string' ? data.label : ''

  return (
    <div className="w-80 bg-background border-l h-full flex flex-col" data-testid="guest-edge-panel">
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2">
          <ArrowRight className="h-5 w-5 text-blue-600" />
          <span className="font-medium">{FLOW_TYPES.find((entry) => entry.value === flowType)?.label ?? 'Flow'}</span>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="edge-label">Name</Label>
          <Input
            id="edge-label"
            value={label}
            onChange={(e) => updateEdgeData({ label: e.target.value })}
            placeholder="e.g., Login request"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="edge-description">Description</Label>
          <Textarea
            id="edge-description"
            value={typeof data.description === 'string' ? data.description : ''}
            onChange={(e) => updateEdgeData({ description: e.target.value })}
            placeholder="What travels on this flow..."
            rows={2}
          />
        </div>

        <div className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm">
          <span className="font-medium truncate">{sourceNode?.data?.label ? String(sourceNode.data.label) : edge.source}</span>
          <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <span className="font-medium truncate">{targetNode?.data?.label ? String(targetNode.data.label) : edge.target}</span>
        </div>

        <Separator />

        <div className="space-y-2">
          <Label htmlFor="edge-flow-type">Flow type</Label>
          <Select value={flowType} onValueChange={(value) => handleFlowTypeChange(value as FlowType)}>
            <SelectTrigger id="edge-flow-type">
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

        {dataLike && (
          <>
            <div className="space-y-2">
              <Label htmlFor="edge-protocol">Protocol</Label>
              <Select
                value={typeof data.protocol === 'string' && data.protocol ? data.protocol : 'none'}
                onValueChange={(value) => updateEdgeData({ protocol: value === 'none' ? undefined : value })}
              >
                <SelectTrigger id="edge-protocol">
                  <SelectValue placeholder="Select protocol..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">Not set</SelectItem>
                  {PROTOCOLS.map((protocol) => (
                    <SelectItem key={protocol} value={protocol}>
                      {protocol}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="edge-port">Port</Label>
              <Input
                id="edge-port"
                type="number"
                min={0}
                max={65535}
                value={typeof data.port === 'number' ? String(data.port) : ''}
                onChange={(e) => {
                  const value = e.target.value.trim()
                  updateEdgeData({ port: value === '' ? undefined : Number.parseInt(value, 10) })
                }}
                placeholder="e.g., 443"
              />
            </div>

            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={data.encrypted === true}
                onCheckedChange={(checked) => updateEdgeData({ encrypted: checked === true })}
              />
              {data.encrypted ? <Lock className="h-3.5 w-3.5 text-green-600" /> : <LockOpen className="h-3.5 w-3.5 text-muted-foreground" />}
              Encrypted in transit
            </label>
          </>
        )}

        <div className="space-y-2">
          <Label>Authentication</Label>
          <p className="text-xs text-muted-foreground">
            {authentication.length === 0
              ? 'Not recorded.'
              : authenticated
                ? 'Authenticated.'
                : 'No authentication.'}
          </p>
          <div className="flex flex-wrap gap-1.5">
            <Button
              type="button"
              variant={authentication.includes(UNSPECIFIED_AUTHENTICATION) ? 'default' : 'outline'}
              size="sm"
              className="h-7 text-xs"
              onClick={() => updateEdgeData({ authentication: normalizeAuthenticationSelection(authentication, [...authentication, UNSPECIFIED_AUTHENTICATION]) })}
            >
              Authenticated, method not specified
            </Button>
            <Button
              type="button"
              variant={authentication.includes(NO_AUTHENTICATION) ? 'default' : 'outline'}
              size="sm"
              className="h-7 text-xs"
              onClick={() => updateEdgeData({ authentication: [NO_AUTHENTICATION] })}
            >
              None
            </Button>
          </div>
          <MultiSelectCombobox
            options={authenticationOptions}
            selected={authentication}
            onChange={(selected) => updateEdgeData({ authentication: normalizeAuthenticationSelection(authentication, selected as AuthenticationType[]) })}
            placeholder="Pick authentication methods..."
            searchPlaceholder="Search methods..."
            allowCustom
          />
        </div>

        <div className="space-y-2">
          <Label>Data classification</Label>
          <MultiSelectCombobox
            options={Object.entries(DATA_SENSITIVITY_TAG_CONFIG).map(([value, config]) => ({ value, label: config.label, description: config.description }))}
            selected={Array.isArray(data.dataClassification) ? (data.dataClassification as string[]) : []}
            onChange={(selected) => updateEdgeData({ dataClassification: selected.length > 0 ? selected : undefined })}
            placeholder="Tag the data on this flow..."
            searchPlaceholder="Search tags..."
          />
        </div>

        <label className="flex items-center gap-2 text-sm">
          <Checkbox
            checked={data.hasSensitiveData === true}
            onCheckedChange={(checked) => updateEdgeData({ hasSensitiveData: checked === true })}
          />
          Carries sensitive data
        </label>

        <Separator />
        <GuestThreatSection target={{ id: edge.id, type: 'flow' }} targetName={label || 'Flow'} />
      </div>

      <div className="p-4 border-t">
        <Button variant="destructive" className="w-full" onClick={handleDelete}>
          <Trash2 className="h-4 w-4 mr-2" />
          Delete Flow
        </Button>
      </div>
    </div>
  )
})
