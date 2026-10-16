import { memo, useMemo, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { X, Trash2, ArrowLeftRight, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { AUTHENTICATION_TYPES, BOUNDARY_TYPES, type BoundaryType } from '@/types/domain'
import type { TrustBoundaryEdge, TrustBoundaryEdgeData } from '../../types'
import { ACCESS_CONTROL_METHODS } from '../../types'
import type { AccessControlMethod, AuthenticationMethod } from '../../types'
import { getBoundaryType } from '../../lib/canvas-defaults'
import {
  normalizeAuthenticationSelection,
  normalizeExclusiveSelection,
} from '../../lib/authentication-selection'
import { AdvancedSection } from './AdvancedSection'

interface TrustBoundaryEdgeEditPanelProps {
  edge: TrustBoundaryEdge
  onClose: () => void
  /** Extra content below the fields, such as the threats scoped to the boundary. */
  renderExtra?: React.ReactNode
}

/**
 * The side panel for a boundary edge (plan 11.2, 4.5).
 *
 * Core: label, boundary type, authentication (the spec list, common methods
 * first), authorization (its six values), the token and logout settings.
 * Advanced: data validation, logging, monitoring, rate limit. The session
 * timeouts, protocols and data transformation have no control here (L2).
 *
 * Canvas keys written: `boundaryType`, `authenticationMethods`,
 * `accessControlMethods`, `dataValidation`, `logging`, `monitoring`,
 * `rateLimit`, plus the seven token and logout keys.
 */
export const TrustBoundaryEdgeEditPanel = memo(function TrustBoundaryEdgeEditPanel({
  edge,
  onClose,
  renderExtra,
}: TrustBoundaryEdgeEditPanelProps) {
  const { setEdges, getNodes } = useReactFlow()
  const [showTokenConfig, setShowTokenConfig] = useState(false)
  const [showLogoutConfig, setShowLogoutConfig] = useState(false)

  const nodes = getNodes()
  const sourceNode = nodes.find((n) => n.id === edge.source)
  const targetNode = nodes.find((n) => n.id === edge.target)

  const boundaryType = getBoundaryType(edge.data)
  const boundaryTypeLabel =
    BOUNDARY_TYPES.find((entry) => entry.value === boundaryType)?.label ?? 'Boundary'
  const authenticationMethods = edge.data?.authenticationMethods ?? []
  const accessControlMethods = edge.data?.accessControlMethods ?? []

  const authenticationOptions = useMemo(
    () => AUTHENTICATION_TYPES.map((entry) => ({ value: entry.value, label: entry.label })),
    []
  )

  const updateEdgeData = (updates: Partial<TrustBoundaryEdgeData>) => {
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

  const handleAuthenticationChange = (selected: string[]) => {
    updateEdgeData({
      authenticationMethods: normalizeAuthenticationSelection(
        authenticationMethods,
        selected
      ) as AuthenticationMethod[],
    })
  }

  const toggleAccessControlMethod = (method: AccessControlMethod) => {
    const next = accessControlMethods.includes(method)
      ? accessControlMethods.filter((m) => m !== method)
      : [...accessControlMethods, method]
    updateEdgeData({
      accessControlMethods: normalizeExclusiveSelection(accessControlMethods, next) as AccessControlMethod[],
    })
  }

  return (
    <div className="w-80 bg-background border-l h-full flex flex-col" data-testid="boundary-panel">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-2 min-w-0">
          <ShieldCheck className="h-5 w-5 text-orange-600 shrink-0" />
          <span className="font-medium">Boundary</span>
          <Badge variant="outline" className="text-[10px] h-5 px-1.5 truncate" title={boundaryTypeLabel}>
            {boundaryTypeLabel}
          </Badge>
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
          <Label htmlFor="boundary-label">Label</Label>
          <Input
            id="boundary-label"
            value={edge.data?.label || ''}
            onChange={(e) => updateEdgeData({ label: e.target.value })}
            placeholder="e.g., API Gateway Boundary..."
          />
        </div>

        {/* Boundary type */}
        <div className="space-y-2">
          <Label htmlFor="boundary-type">Type</Label>
          <Select
            value={boundaryType}
            onValueChange={(value) => updateEdgeData({ boundaryType: value as BoundaryType })}
          >
            <SelectTrigger id="boundary-type" data-testid="boundary-type-select">
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
          <p className="text-xs text-muted-foreground">
            Two boundaries of different types may join the same two zones.
          </p>
        </div>

        <Separator />

        {/* Authentication: the spec list, common methods first */}
        <div className="space-y-2">
          <Label>Authentication</Label>
          <MultiSelectCombobox
            options={authenticationOptions}
            selected={authenticationMethods}
            onChange={handleAuthenticationChange}
            placeholder="Add a method..."
            searchPlaceholder="Search methods or type a custom name..."
            allowCustom
          />
          <p className="text-xs text-muted-foreground">
            Empty means not recorded. "None" means no authentication is required.
          </p>
        </div>

        <Separator />

        {/* Authorization: the six values the panel has always had */}
        <div className="space-y-2">
          <Label>Authorization</Label>
          <div className="grid grid-cols-2 gap-2">
            {ACCESS_CONTROL_METHODS.map((method) => (
              <div key={method.value} className="flex items-center space-x-2">
                <Checkbox
                  id={`acl-${method.value}`}
                  checked={accessControlMethods.includes(method.value)}
                  onCheckedChange={() => toggleAccessControlMethod(method.value)}
                />
                <Label
                  htmlFor={`acl-${method.value}`}
                  className="text-sm font-normal cursor-pointer"
                >
                  {method.label}
                </Label>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Token Configuration (collapsible) */}
        <div className="space-y-2">
          <button
            className="flex items-center gap-2 w-full text-left"
            onClick={() => setShowTokenConfig(!showTokenConfig)}
          >
            {showTokenConfig ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <Label className="cursor-pointer">Token Configuration</Label>
          </button>

          {showTokenConfig && (
            <div className="space-y-3 pl-6">
              <div className="flex items-center justify-between">
                <Label htmlFor="access-token-expires" className="text-sm font-normal">
                  Access token expires
                </Label>
                <Switch
                  id="access-token-expires"
                  checked={edge.data?.accessTokenExpires || false}
                  onCheckedChange={(checked) =>
                    updateEdgeData({ accessTokenExpires: checked })
                  }
                />
              </div>

              {edge.data?.accessTokenExpires && (
                <div className="space-y-1">
                  <Label htmlFor="access-token-ttl" className="text-xs text-muted-foreground">
                    Access token TTL (seconds)
                  </Label>
                  <Input
                    id="access-token-ttl"
                    type="number"
                    min={0}
                    value={edge.data?.accessTokenTtl ?? ''}
                    onChange={(e) =>
                      updateEdgeData({
                        accessTokenTtl: e.target.value ? parseInt(e.target.value, 10) : undefined,
                      })
                    }
                    placeholder="e.g., 3600"
                  />
                </div>
              )}

              <div className="flex items-center justify-between">
                <Label htmlFor="has-refresh-token" className="text-sm font-normal">
                  Has refresh token
                </Label>
                <Switch
                  id="has-refresh-token"
                  checked={edge.data?.hasRefreshToken || false}
                  onCheckedChange={(checked) =>
                    updateEdgeData({ hasRefreshToken: checked })
                  }
                />
              </div>

              {edge.data?.hasRefreshToken && (
                <>
                  <div className="flex items-center justify-between">
                    <Label htmlFor="refresh-token-expires" className="text-sm font-normal">
                      Refresh token expires
                    </Label>
                    <Switch
                      id="refresh-token-expires"
                      checked={edge.data?.refreshTokenExpires || false}
                      onCheckedChange={(checked) =>
                        updateEdgeData({ refreshTokenExpires: checked })
                      }
                    />
                  </div>

                  {edge.data?.refreshTokenExpires && (
                    <div className="space-y-1">
                      <Label htmlFor="refresh-token-ttl" className="text-xs text-muted-foreground">
                        Refresh token TTL (seconds)
                      </Label>
                      <Input
                        id="refresh-token-ttl"
                        type="number"
                        min={0}
                        value={edge.data?.refreshTokenTtl ?? ''}
                        onChange={(e) =>
                          updateEdgeData({
                            refreshTokenTtl: e.target.value
                              ? parseInt(e.target.value, 10)
                              : undefined,
                          })
                        }
                        placeholder="e.g., 86400"
                      />
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        <Separator />

        {/* Logout Capabilities (collapsible) */}
        <div className="space-y-2">
          <button
            className="flex items-center gap-2 w-full text-left"
            onClick={() => setShowLogoutConfig(!showLogoutConfig)}
          >
            {showLogoutConfig ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <Label className="cursor-pointer">Logout Capabilities</Label>
          </button>

          {showLogoutConfig && (
            <div className="space-y-3 pl-6">
              <div className="flex items-center justify-between">
                <Label htmlFor="can-user-logout" className="text-sm font-normal">
                  Can user logout
                </Label>
                <Switch
                  id="can-user-logout"
                  checked={edge.data?.canUserLogout || false}
                  onCheckedChange={(checked) =>
                    updateEdgeData({ canUserLogout: checked })
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="can-system-logout" className="text-sm font-normal">
                  Can system logout
                </Label>
                <Switch
                  id="can-system-logout"
                  checked={edge.data?.canSystemLogout || false}
                  onCheckedChange={(checked) =>
                    updateEdgeData({ canSystemLogout: checked })
                  }
                />
              </div>
            </div>
          )}
        </div>

        <Separator />

        {/* Advanced: the crossing requirements with a checkbox or a line of text */}
        <AdvancedSection>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="boundary-data-validation"
              checked={edge.data?.dataValidation === true}
              onCheckedChange={(checked) => updateEdgeData({ dataValidation: checked === true })}
            />
            <Label htmlFor="boundary-data-validation" className="text-sm font-normal cursor-pointer">
              Data is validated when crossing
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="boundary-logging"
              checked={edge.data?.logging === true}
              onCheckedChange={(checked) => updateEdgeData({ logging: checked === true })}
            />
            <Label htmlFor="boundary-logging" className="text-sm font-normal cursor-pointer">
              Crossings are logged
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Checkbox
              id="boundary-monitoring"
              checked={edge.data?.monitoring === true}
              onCheckedChange={(checked) => updateEdgeData({ monitoring: checked === true })}
            />
            <Label htmlFor="boundary-monitoring" className="text-sm font-normal cursor-pointer">
              Crossings are monitored
            </Label>
          </div>
          <div className="space-y-1">
            <Label htmlFor="boundary-rate-limit" className="text-sm font-normal">
              Rate limit
            </Label>
            <Input
              id="boundary-rate-limit"
              value={edge.data?.rateLimit ?? ''}
              maxLength={255}
              onChange={(e) =>
                updateEdgeData({ rateLimit: e.target.value === '' ? undefined : e.target.value })
              }
              placeholder="e.g., 100 requests per minute"
            />
          </div>
        </AdvancedSection>

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
          Delete Boundary
        </Button>
      </div>
    </div>
  )
})
