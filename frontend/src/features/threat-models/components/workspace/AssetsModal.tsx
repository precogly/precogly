/**
 * Data assets of a model. Each asset belongs to a blueprint (plan J8): with
 * more than one blueprint the form shows a blueprint select preset to the
 * switcher's blueprint and the list is grouped by blueprint; with one
 * blueprint nothing of this is visible.
 */

import { useState, useMemo } from 'react'
import { Plus, Trash2, Pencil, X, Check, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ScrollArea } from '@/components/ui/scroll-area'
import { MultiSelectCombobox } from '@/components/ui/multi-select-combobox'
import { cn } from '@/lib/utils'
import {
  type AssetClassification,
  ASSET_CLASSIFICATION_CONFIG,
} from '@/features/dfd-editor/types/threat-analysis'
import {
  type DataSensitivityTag,
  DATA_SENSITIVITY_TAG_CONFIG,
} from '@/types/domain'
import {
  useDataAssets,
  useCreateDataAsset,
  useUpdateDataAsset,
  useDeleteDataAsset,
  type DataAsset,
} from '@/features/threat-models/api/data-assets'
import type { Blueprint } from '@/features/threat-models/types/core'
import { groupByBlueprint, resolveSelectedBlueprintId, showsBlueprintChoice, sortBlueprints } from './blueprint-utils'

interface AssetsModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  blueprints: Blueprint[]
  /** The switcher's blueprint; new assets go there unless the form says otherwise. */
  selectedBlueprintId: number | null
}

export function AssetsModal({ open, onOpenChange, threatModelId, blueprints, selectedBlueprintId }: AssetsModalProps) {
  const { data: assets = [], isLoading } = useDataAssets(threatModelId)
  const createAssetMutation = useCreateDataAsset()
  const updateAssetMutation = useUpdateDataAsset()
  const deleteAssetMutation = useDeleteDataAsset()

  const [editingId, setEditingId] = useState<number | null>(null)
  const [isAdding, setIsAdding] = useState(false)

  // Form state for add/edit
  const [formName, setFormName] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [formClassification, setFormClassification] = useState<AssetClassification>('other')
  const [formDataSensitivity, setFormDataSensitivity] = useState<DataSensitivityTag[]>([])
  // Null means "the switcher's blueprint"; set when the user picks another or edits a row.
  const [formBlueprintChoice, setFormBlueprintChoice] = useState<number | null>(null)
  const formBlueprintId = formBlueprintChoice ?? resolveSelectedBlueprintId(selectedBlueprintId, blueprints)
  const setFormBlueprintId = setFormBlueprintChoice

  const showBlueprintChoice = showsBlueprintChoice(blueprints)

  const resetForm = () => {
    setFormName('')
    setFormDescription('')
    setFormClassification('other')
    setFormDataSensitivity([])
    setFormBlueprintChoice(null)
    setEditingId(null)
    setIsAdding(false)
  }

  const handleStartAdd = () => {
    resetForm()
    setIsAdding(true)
  }

  const handleStartEdit = (asset: DataAsset) => {
    setFormName(asset.name)
    setFormDescription(asset.description)
    setFormClassification(asset.classification as AssetClassification)
    setFormDataSensitivity((asset.dataSensitivity || []) as DataSensitivityTag[])
    setFormBlueprintChoice(asset.blueprint ?? null)
    setEditingId(asset.id)
    setIsAdding(false)
  }

  const dataSensitivityOptions = useMemo(
    () =>
      Object.entries(DATA_SENSITIVITY_TAG_CONFIG).map(([value, config]) => ({
        value,
        label: config.label,
        description: config.description,
      })),
    []
  )

  const handleSaveAsset = () => {
    if (!formName.trim()) return
    const blueprint = formBlueprintId
    if (blueprint === null) return

    if (editingId) {
      updateAssetMutation.mutate(
        {
          id: editingId,
          data: {
            name: formName.trim(),
            description: formDescription.trim(),
            classification: formClassification,
            dataSensitivity: formDataSensitivity,
            blueprint,
          },
        },
        { onSuccess: () => resetForm() }
      )
    } else {
      createAssetMutation.mutate(
        {
          name: formName.trim(),
          description: formDescription.trim(),
          classification: formClassification,
          dataSensitivity: formDataSensitivity,
          blueprint,
        },
        { onSuccess: () => resetForm() }
      )
    }
  }

  const handleDelete = (id: number) => {
    deleteAssetMutation.mutate(id)
    if (editingId === id) {
      resetForm()
    }
  }

  const isSaving = createAssetMutation.isPending || updateAssetMutation.isPending

  const renderAsset = (asset: DataAsset) => (
    <div
      key={asset.id}
      className={cn('flex items-start justify-between p-3 rounded', editingId === asset.id ? 'bg-muted' : 'hover:bg-muted')}
      data-testid="data-asset-row"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium">{asset.name}</span>
          <span className="text-xs px-2 py-0.5 bg-amber-100 text-amber-700 rounded">
            {ASSET_CLASSIFICATION_CONFIG[asset.classification as AssetClassification]?.label || asset.classification}
          </span>
          {asset.dataSensitivity?.map((tag) => (
            <span key={tag} className="text-xs px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded">
              {DATA_SENSITIVITY_TAG_CONFIG[tag as DataSensitivityTag]?.label || tag}
            </span>
          ))}
        </div>
        {asset.description && <div className="text-xs text-muted-foreground mt-1">{asset.description}</div>}
      </div>
      <div className="flex items-center gap-1 ml-2">
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleStartEdit(asset)}>
          <Pencil className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:text-destructive"
          onClick={() => handleDelete(asset.id)}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Data assets</DialogTitle>
          <DialogDescription>The primary assets that need protection in this system.</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Asset list */}
          <ScrollArea className="h-[250px] border rounded-md">
            <div className="p-2 space-y-1">
              {isLoading ? (
                <div className="p-8 text-center">
                  <Loader2 className="h-5 w-5 animate-spin mx-auto text-muted-foreground" />
                </div>
              ) : assets.length === 0 ? (
                <div className="p-8 text-center text-sm text-muted-foreground">No data assets defined yet</div>
              ) : showBlueprintChoice ? (
                groupByBlueprint(assets, blueprints).map((group) => (
                  <div key={group.blueprint?.id ?? 'unassigned'} className="space-y-1">
                    <div className="px-3 pt-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      {group.blueprint?.name ?? 'No blueprint'}
                    </div>
                    {group.items.map(renderAsset)}
                  </div>
                ))
              ) : (
                assets.map(renderAsset)
              )}
            </div>
          </ScrollArea>

          {/* Add/Edit form */}
          {(isAdding || editingId) && (
            <div className="border rounded-md p-4 space-y-3 bg-muted/50">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{editingId ? 'Edit asset' : 'New asset'}</span>
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={resetForm}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
              {showBlueprintChoice && (
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Blueprint</label>
                  <Select
                    value={formBlueprintId !== null ? String(formBlueprintId) : ''}
                    onValueChange={(value) => setFormBlueprintId(Number(value))}
                  >
                    <SelectTrigger className="h-8 text-sm" aria-label="Blueprint">
                      <SelectValue placeholder="Choose a blueprint" />
                    </SelectTrigger>
                    <SelectContent>
                      {sortBlueprints(blueprints).map((blueprint) => (
                        <SelectItem key={blueprint.id} value={String(blueprint.id)}>
                          {blueprint.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Name</label>
                  <Input placeholder="e.g., Customer Data" value={formName} onChange={(e) => setFormName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Classification</label>
                  <Select value={formClassification} onValueChange={(v) => setFormClassification(v as AssetClassification)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(ASSET_CLASSIFICATION_CONFIG).map(([key, config]) => (
                        <SelectItem key={key} value={key}>
                          {config.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium">Description</label>
                <Textarea
                  placeholder="Describe the asset..."
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  rows={2}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium">Data sensitivity</label>
                <MultiSelectCombobox
                  options={dataSensitivityOptions}
                  selected={formDataSensitivity}
                  onChange={setFormDataSensitivity}
                  placeholder="Select or add tags..."
                  searchPlaceholder="Search or type custom..."
                  allowCustom
                />
              </div>
              <div className="flex justify-end">
                <Button
                  size="sm"
                  onClick={handleSaveAsset}
                  disabled={!formName.trim() || formBlueprintId === null || isSaving}
                  className="gap-1"
                >
                  {isSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
                  {editingId ? 'Update' : 'Add'}
                </Button>
              </div>
            </div>
          )}

          {/* Add button */}
          {!isAdding && !editingId && (
            <Button variant="outline" onClick={handleStartAdd} className="w-full gap-2">
              <Plus className="h-4 w-4" />
              Add data asset
            </Button>
          )}

          {/* Actions */}
          <div className="flex justify-end pt-2 border-t">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
