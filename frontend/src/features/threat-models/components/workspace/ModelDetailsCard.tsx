/**
 * The Details card of the model page (plan 11.5, 11.11 "Model" row).
 *
 * Core: description, methodologies, the primary system (one optional
 * inventory system, with "Create new system", plan J1) and the read-only
 * list of system assets drawn in the blueprints. Advanced: serial number and
 * version with "Copy BOM-Link" (plan J9).
 */

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Copy, FileText, Pencil, Server } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DEFAULT_METHODOLOGIES, METHODOLOGIES } from '@/types/domain'
import { bomLink, useSystems, useUpdateThreatModel } from '@/features/threat-models/api/threat-models'
import { useAnalysisComponents } from '@/features/threat-models/api/components'
import type { Blueprint, System, ThreatModel } from '@/features/threat-models/types/core'
import { SystemFormDialog } from '@/features/threat-models/components/SystemFormDialog'
import { blueprintName, showsBlueprintChoice } from './blueprint-utils'

const PRIMARY_SYSTEM_NONE = 'none'
const PRIMARY_SYSTEM_CREATE = 'create-new'

interface ModelDetailsCardProps {
  threatModel: ThreatModel
  blueprints: Blueprint[]
  onEditDescription: () => void
}

export function ModelDetailsCard({ threatModel, blueprints, onEditDescription }: ModelDetailsCardProps) {
  const threatModelId = threatModel.id
  const updateThreatModelMutation = useUpdateThreatModel()
  const { data: systems = [] } = useSystems()
  const { data: components = [] } = useAnalysisComponents(threatModelId)

  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [createSystemOpen, setCreateSystemOpen] = useState(false)

  const methodologyOptions = useMemo(() => {
    const known = METHODOLOGIES.map((option) => ({ value: option.value, label: option.label }))
    const custom = (threatModel.methodologies ?? [])
      .filter((name) => !METHODOLOGIES.some((option) => option.value === name))
      .map((name) => ({ value: name, label: name }))
    return [...known, ...custom]
  }, [threatModel.methodologies])

  const systemAssets = useMemo(
    () =>
      components.filter(
        (component) => component.effectiveKind === 'system' || component.effectiveKind === 'subsystem'
      ),
    [components]
  )

  const systemsById = useMemo(() => new Map(systems.map((system) => [system.id, system])), [systems])
  const modelBomLink = bomLink(threatModel)

  const save = (data: Partial<ThreatModel>) => {
    updateThreatModelMutation.mutate(
      { id: threatModelId, data },
      { onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not save') }
    )
  }

  const handlePrimarySystemChange = (value: string) => {
    if (value === PRIMARY_SYSTEM_CREATE) {
      setCreateSystemOpen(true)
      return
    }
    save({ primarySystem: value === PRIMARY_SYSTEM_NONE ? null : Number(value) })
  }

  const handleSystemCreated = (system: System) => {
    save({ primarySystem: system.id })
  }

  const handleCopyBomLink = async () => {
    if (!modelBomLink) return
    try {
      await navigator.clipboard.writeText(modelBomLink)
      toast.success('BOM-Link copied')
    } catch {
      toast.error('Could not copy. The link is: ' + modelBomLink)
    }
  }

  return (
    <Card data-testid="model-details-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <FileText className="h-4 w-4 text-muted-foreground" />
          Details
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <Label className="text-xs text-muted-foreground">Description</Label>
            <Button variant="ghost" size="sm" className="h-6 gap-1 px-2 text-xs" onClick={onEditDescription}>
              <Pencil className="h-3 w-3" />
              Edit
            </Button>
          </div>
          <p className="text-sm whitespace-pre-line">
            {threatModel.description || <span className="text-muted-foreground">No description yet.</span>}
          </p>
        </div>

        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">Methodologies</Label>
          <MultiSelectCombobox
            options={methodologyOptions}
            selected={threatModel.methodologies ?? DEFAULT_METHODOLOGIES}
            onChange={(selected) => save({ methodologies: selected })}
            placeholder="Choose methodologies"
            searchPlaceholder="Search or type a custom name"
            allowCustom
          />
        </div>

        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground" htmlFor="primary-system-select">
            Primary system
          </Label>
          <Select
            value={threatModel.primarySystem != null ? String(threatModel.primarySystem) : PRIMARY_SYSTEM_NONE}
            onValueChange={handlePrimarySystemChange}
          >
            <SelectTrigger id="primary-system-select" className="h-8 text-sm" data-testid="primary-system-select">
              <SelectValue placeholder="No primary system" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={PRIMARY_SYSTEM_NONE}>No primary system</SelectItem>
              {systems.map((system) => (
                <SelectItem key={system.id} value={String(system.id)}>
                  {system.name}
                </SelectItem>
              ))}
              <SelectSeparator />
              <SelectItem value={PRIMARY_SYSTEM_CREATE}>+ Create new system</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            One model is about one system. Without one, the export is named after the model.
          </p>
        </div>

        <div className="space-y-1">
          <Label className="text-xs text-muted-foreground">System assets in the blueprints</Label>
          {systemAssets.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No system boxes drawn yet. Other systems this one touches are drawn on the diagram.
            </p>
          ) : (
            <ul className="space-y-1" data-testid="system-assets-list">
              {systemAssets.map((asset) => {
                const linkedSystem = asset.orgsystem != null ? systemsById.get(asset.orgsystem) : undefined
                return (
                  <li key={asset.id} className="flex items-center gap-2 text-sm">
                    <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="truncate">{asset.name}</span>
                    {linkedSystem && (
                      <Badge variant="outline" className="text-xs font-normal">
                        {linkedSystem.name}
                      </Badge>
                    )}
                    {showsBlueprintChoice(blueprints) && (
                      <span className="text-xs text-muted-foreground">{blueprintName(asset.blueprint, blueprints)}</span>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        <div>
          <button
            type="button"
            className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
            onClick={() => setAdvancedOpen((open) => !open)}
            aria-expanded={advancedOpen}
          >
            {advancedOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            Advanced
          </button>
          {advancedOpen && (
            <dl className="mt-3 space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <dt className="w-28 shrink-0 text-xs text-muted-foreground">Serial number</dt>
                <dd className="font-mono text-xs break-all">{threatModel.serialNumber || 'Assigned on first export'}</dd>
              </div>
              <div className="flex items-center gap-2">
                <dt className="w-28 shrink-0 text-xs text-muted-foreground">Version</dt>
                <dd className="font-mono text-xs">{threatModel.version ?? 1}</dd>
              </div>
              <div className="flex items-center gap-2">
                <dt className="w-28 shrink-0 text-xs text-muted-foreground">BOM-Link</dt>
                <dd className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-xs truncate">{modelBomLink ?? 'Not available yet'}</span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-6 gap-1 px-2 text-xs"
                    onClick={handleCopyBomLink}
                    disabled={!modelBomLink}
                  >
                    <Copy className="h-3 w-3" />
                    Copy BOM-Link
                  </Button>
                </dd>
              </div>
            </dl>
          )}
        </div>
      </CardContent>

      <SystemFormDialog open={createSystemOpen} onOpenChange={setCreateSystemOpen} onSaved={handleSystemCreated} />
    </Card>
  )
}
