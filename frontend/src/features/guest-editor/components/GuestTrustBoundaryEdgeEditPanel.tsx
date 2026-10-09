import { memo } from 'react'
import { useReactFlow } from '@xyflow/react'
import { X, Trash2, ArrowLeftRight, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
import type { DiagramNode, TrustBoundaryEdge } from '@/features/dfd-editor/types'
import {
  AUTHENTICATION_TYPES,
  AUTHORIZATION_TYPES,
  BOUNDARY_TYPES,
  NO_AUTHENTICATION,
  UNSPECIFIED_AUTHENTICATION,
  type BoundaryType,
} from '@/types/domain'
import { getBoundaryType, isAuthenticated } from '@/features/dfd-editor/lib/canvas-defaults'
import { normalizeAuthenticationSelection, normalizeExclusiveSelection } from '@/features/dfd-editor/lib/authentication-selection'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GuestThreatSection } from './GuestThreatSection'

interface GuestTrustBoundaryEdgeEditPanelProps {
  edge: TrustBoundaryEdge
  onClose: () => void
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

/**
 * The guest editor's side panel for a boundary (plan 11.9): boundary type,
 * the crossing requirements (authentication, authorization, validation,
 * logging, monitoring, rate limit), the token and logout settings and the
 * threat section. Writes the same canvas keys as the signed-in editor.
 */
export const GuestTrustBoundaryEdgeEditPanel = memo(function GuestTrustBoundaryEdgeEditPanel({
  edge,
  onClose,
}: GuestTrustBoundaryEdgeEditPanelProps) {
  const { setEdges, getNodes } = useReactFlow()
  const guestEditor = useGuestEditor()

  const nodes = getNodes() as DiagramNode[]
  const sourceNode = nodes.find((node) => node.id === edge.source)
  const targetNode = nodes.find((node) => node.id === edge.target)
  const data = edge.data ?? {}
  const boundaryType = getBoundaryType(data)
  const authentication = stringList(data.authenticationMethods)
  const authorization = stringList(data.accessControlMethods)
  const label = typeof data.label === 'string' ? data.label : ''

  const updateEdgeData = (updates: Record<string, unknown>) => {
    setEdges((edges) =>
      edges.map((candidate) => (candidate.id === edge.id ? { ...candidate, data: { ...candidate.data, ...updates } } : candidate))
    )
  }

  const handleDelete = () => {
    guestEditor?.removeDiagramElements([edge.id])
    setEdges((edges) => edges.filter((candidate) => candidate.id !== edge.id))
    onClose()
  }

  const booleanField = (key: string, text: string) => (
    <label key={key} className="flex items-center gap-2 text-sm">
      <Checkbox checked={data[key] === true} onCheckedChange={(checked) => updateEdgeData({ [key]: checked === true })} />
      {text}
    </label>
  )

  const ttlField = (key: string, text: string) => (
    <div key={key} className="space-y-1">
      <Label htmlFor={`boundary-${key}`} className="text-xs">{text}</Label>
      <Input
        id={`boundary-${key}`}
        type="number"
        min={0}
        value={typeof data[key] === 'number' ? String(data[key]) : ''}
        onChange={(e) => {
          const value = e.target.value.trim()
          updateEdgeData({ [key]: value === '' ? undefined : Number.parseInt(value, 10) })
        }}
        placeholder="seconds"
      />
    </div>
  )

  return (
    <div className="w-80 bg-background border-l h-full flex flex-col" data-testid="guest-boundary-panel">
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-orange-600" />
          <span className="font-medium">{BOUNDARY_TYPES.find((entry) => entry.value === boundaryType)?.label ?? 'Boundary'}</span>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="boundary-label">Name</Label>
          <Input
            id="boundary-label"
            value={label}
            onChange={(e) => updateEdgeData({ label: e.target.value })}
            placeholder="e.g., Internet edge"
          />
        </div>

        <div className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-sm">
          <span className="font-medium truncate">{sourceNode?.data?.label ? String(sourceNode.data.label) : edge.source}</span>
          <ArrowLeftRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <span className="font-medium truncate">{targetNode?.data?.label ? String(targetNode.data.label) : edge.target}</span>
        </div>

        <div className="space-y-2">
          <Label htmlFor="boundary-type">Boundary type</Label>
          <Select value={boundaryType} onValueChange={(value) => updateEdgeData({ boundaryType: value as BoundaryType })}>
            <SelectTrigger id="boundary-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {BOUNDARY_TYPES.map((entry) => (
                <SelectItem key={entry.value} value={entry.value}>
                  {entry.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Separator />

        <div className="space-y-2">
          <Label>Authentication to cross</Label>
          <p className="text-xs text-muted-foreground">
            {authentication.length === 0 ? 'Not recorded.' : isAuthenticated(authentication) ? 'Required.' : 'Not required.'}
          </p>
          <div className="flex flex-wrap gap-1.5">
            <Button
              type="button"
              variant={authentication.includes(UNSPECIFIED_AUTHENTICATION) ? 'default' : 'outline'}
              size="sm"
              className="h-7 text-xs"
              onClick={() => updateEdgeData({ authenticationMethods: normalizeAuthenticationSelection(authentication, [...authentication, UNSPECIFIED_AUTHENTICATION]) })}
            >
              Required, method not specified
            </Button>
            <Button
              type="button"
              variant={authentication.includes(NO_AUTHENTICATION) ? 'default' : 'outline'}
              size="sm"
              className="h-7 text-xs"
              onClick={() => updateEdgeData({ authenticationMethods: [NO_AUTHENTICATION] })}
            >
              None
            </Button>
          </div>
          <MultiSelectCombobox
            options={AUTHENTICATION_TYPES.map((entry) => ({ value: entry.value, label: entry.label }))}
            selected={authentication}
            onChange={(selected) => updateEdgeData({ authenticationMethods: normalizeAuthenticationSelection(authentication, selected) })}
            placeholder="Pick authentication methods..."
            searchPlaceholder="Search methods..."
            allowCustom
          />
        </div>

        <div className="space-y-2">
          <Label>Authorization to cross</Label>
          <MultiSelectCombobox
            options={AUTHORIZATION_TYPES.map((entry) => ({ value: entry.value, label: entry.label }))}
            selected={authorization}
            onChange={(selected) => updateEdgeData({ accessControlMethods: normalizeExclusiveSelection(authorization, selected) })}
            placeholder="Pick authorization models..."
            searchPlaceholder="Search models..."
            allowCustom
          />
        </div>

        <div className="space-y-2">
          <Label>Crossing requirements</Label>
          <div className="space-y-1.5">
            {booleanField('dataValidation', 'Data validation')}
            {booleanField('logging', 'Logging')}
            {booleanField('monitoring', 'Monitoring')}
          </div>
          <div className="space-y-1">
            <Label htmlFor="boundary-rate-limit" className="text-xs">Rate limit</Label>
            <Input
              id="boundary-rate-limit"
              value={typeof data.rateLimit === 'string' ? data.rateLimit : ''}
              onChange={(e) => updateEdgeData({ rateLimit: e.target.value || undefined })}
              placeholder="e.g., 100 requests per second"
            />
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <Label>Session management</Label>
          <div className="space-y-1.5">
            {booleanField('accessTokenExpires', 'Access token expires')}
            {data.accessTokenExpires === true && ttlField('accessTokenTtl', 'Access token lifetime')}
            {booleanField('hasRefreshToken', 'Refresh token issued')}
            {data.hasRefreshToken === true && booleanField('refreshTokenExpires', 'Refresh token expires')}
            {data.hasRefreshToken === true && data.refreshTokenExpires === true && ttlField('refreshTokenTtl', 'Refresh token lifetime')}
            {booleanField('canUserLogout', 'User can log out')}
            {booleanField('canSystemLogout', 'System can end the session')}
          </div>
        </div>

        <Separator />
        <GuestThreatSection target={{ id: edge.id, type: 'boundary' }} targetName={label || 'Boundary'} />
      </div>

      <div className="p-4 border-t">
        <Button variant="destructive" className="w-full" onClick={handleDelete}>
          <Trash2 className="h-4 w-4 mr-2" />
          Delete Boundary
        </Button>
      </div>
    </div>
  )
})
