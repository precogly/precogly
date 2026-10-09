/**
 * The system context dialog (plan 11.5, mockup 06): description and
 * criticality of the model, the data assets, the out-of-scope items and the
 * assumptions. The lock is gone. Assumptions, out-of-scope items and data
 * assets belong to a blueprint (J8): with more than one blueprint a select
 * preset to the switcher's blueprint appears; with one, nothing is visible.
 */

import { useState } from 'react'
import { FileText, ShieldX, Package, ClipboardList } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { useThreatModel, useUpdateThreatModel, useAssumptions } from '@/features/threat-models/api/threat-models'
import { useDataAssets } from '@/features/threat-models/api/data-assets'
import { useOutOfScopeItems } from '@/features/threat-models/api/out-of-scope-items'
import type { Blueprint, ThreatModel } from '@/features/threat-models/types/core'
import type { Criticality } from '@/types/domain'
import { AssetsModal } from './AssetsModal'
import { OutOfScopeModal } from './OutOfScopeModal'
import { AssumptionsEditor } from './AssumptionsEditor'
import { resolveSelectedBlueprintId, showsBlueprintChoice, sortBlueprints } from './blueprint-utils'

type ActiveView = 'assets' | 'out-of-scope' | 'describe' | 'assumptions'

const CRITICALITY_OPTIONS: { value: Criticality; label: string }[] = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

interface SystemContextModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
  blueprints: Blueprint[]
  /** The switcher's blueprint, preset in the dialog's own select. */
  selectedBlueprintId: number | null
}

export function SystemContextModal({
  open,
  onOpenChange,
  threatModelId,
  blueprints,
  selectedBlueprintId,
}: SystemContextModalProps) {
  const { data: threatModel } = useThreatModel(threatModelId)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl" data-testid="system-context-modal">
        {/* The content unmounts when the dialog closes, so the body starts from the model on every open. */}
        {threatModel && (
          <SystemContextBody
            threatModel={threatModel}
            blueprints={blueprints}
            selectedBlueprintId={selectedBlueprintId}
            onClose={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

interface SystemContextBodyProps {
  threatModel: ThreatModel
  blueprints: Blueprint[]
  selectedBlueprintId: number | null
  onClose: () => void
}

function SystemContextBody({ threatModel, blueprints, selectedBlueprintId, onClose }: SystemContextBodyProps) {
  const threatModelId = threatModel.id
  const { data: assets = [] } = useDataAssets(threatModelId)
  const { data: outOfScopeItems = [] } = useOutOfScopeItems(threatModelId)
  const { data: assumptions = [] } = useAssumptions(threatModelId)
  const updateThreatModelMutation = useUpdateThreatModel()

  const [description, setDescription] = useState(threatModel.description || '')
  const [criticality, setCriticality] = useState<Criticality>(threatModel.criticality ?? 'medium')
  const [activeView, setActiveView] = useState<ActiveView>('describe')
  // Null means "the switcher's blueprint"; set when the user picks another one here.
  const [blueprintChoice, setBlueprintChoice] = useState<number | null>(null)
  const activeBlueprintId = blueprintChoice ?? resolveSelectedBlueprintId(selectedBlueprintId, blueprints)

  // Sub-modal states
  const [assetsModalOpen, setAssetsModalOpen] = useState(false)
  const [outOfScopeModalOpen, setOutOfScopeModalOpen] = useState(false)

  const showBlueprintChoice = showsBlueprintChoice(blueprints)

  const handleSave = () => {
    updateThreatModelMutation.mutate({
      id: threatModelId,
      data: {
        description,
        criticality,
      } as Partial<ThreatModel>,
    })
    onClose()
  }

  const handleAssetsClick = () => {
    setActiveView('assets')
    setAssetsModalOpen(true)
  }

  const handleOutOfScopeClick = () => {
    setActiveView('out-of-scope')
    setOutOfScopeModalOpen(true)
  }

  const inActiveBlueprint = <T extends { blueprint?: number | null }>(rows: T[]): T[] =>
    showBlueprintChoice && activeBlueprintId !== null
      ? rows.filter((row) => row.blueprint === activeBlueprintId)
      : rows
  const blueprintScopedAssumptions = inActiveBlueprint(assumptions)
  const blueprintScopedAssets = inActiveBlueprint(assets)
  const blueprintScopedOutOfScope = inActiveBlueprint(outOfScopeItems)

  return (
    <>
      <DialogHeader>
        <div className="flex items-center justify-between gap-3 pr-6">
          <DialogTitle>System context</DialogTitle>
          {showBlueprintChoice && (
            <Select
              value={activeBlueprintId !== null ? String(activeBlueprintId) : ''}
              onValueChange={(value) => setBlueprintChoice(Number(value))}
            >
              <SelectTrigger
                className="h-8 w-[220px] text-xs"
                aria-label="Blueprint"
                data-testid="context-blueprint-select"
              >
                <span className="text-muted-foreground mr-1">Blueprint:</span>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {sortBlueprints(blueprints).map((blueprint) => (
                  <SelectItem key={blueprint.id} value={String(blueprint.id)}>
                    {blueprint.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
        <DialogDescription>
          What the system is, what it protects, what is left out and what the model takes as true.
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-6 py-4">
        {/* Criticality */}
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium">Criticality</span>
          <Select value={criticality} onValueChange={(value) => setCriticality(value as Criticality)}>
            <SelectTrigger className="w-[140px] h-8 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CRITICALITY_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Context buttons */}
        <div className="grid grid-cols-4 gap-3">
          <ContextButton
            icon={Package}
            label="Data assets"
            count={blueprintScopedAssets.length}
            onClick={handleAssetsClick}
            active={activeView === 'assets'}
          />
          <ContextButton
            icon={ShieldX}
            label="Out of scope"
            count={blueprintScopedOutOfScope.length}
            onClick={handleOutOfScopeClick}
            active={activeView === 'out-of-scope'}
          />
          <ContextButton
            icon={FileText}
            label="Describe system"
            onClick={() => setActiveView('describe')}
            active={activeView === 'describe'}
          />
          <ContextButton
            icon={ClipboardList}
            label="Assumptions"
            count={blueprintScopedAssumptions.length}
            onClick={() => setActiveView('assumptions')}
            active={activeView === 'assumptions'}
          />
        </div>

        {activeView === 'describe' && (
          <div className="space-y-2">
            <Textarea
              placeholder="Type out the system description ..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={6}
            />
          </div>
        )}

        {activeView === 'assets' && (
          <div className="border rounded-md p-4 bg-muted/30">
            <div className="text-sm text-muted-foreground">
              {blueprintScopedAssets.length === 0 ? (
                'No data assets defined. Click the button above to add assets.'
              ) : (
                <>
                  <span className="font-medium">{blueprintScopedAssets.length}</span> data asset
                  {blueprintScopedAssets.length !== 1 ? 's' : ''} defined. Click the button above to manage them.
                </>
              )}
            </div>
          </div>
        )}

        {activeView === 'out-of-scope' && (
          <div className="border rounded-md p-4 bg-muted/30">
            <div className="text-sm text-muted-foreground">
              {blueprintScopedOutOfScope.length === 0 ? (
                'No out of scope items defined. Click the button above to add items.'
              ) : (
                <>
                  <span className="font-medium">{blueprintScopedOutOfScope.length}</span> item
                  {blueprintScopedOutOfScope.length !== 1 ? 's' : ''} marked out of scope. Click the button above to
                  manage them.
                </>
              )}
            </div>
          </div>
        )}

        {activeView === 'assumptions' && (
          <AssumptionsEditor
            threatModelId={threatModelId}
            blueprintId={showBlueprintChoice ? activeBlueprintId : (blueprints[0]?.id ?? null)}
          />
        )}

        {/* Actions */}
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            Assets, out-of-scope items and assumptions save as you go. Submit saves the description and criticality.
          </span>
          <Button onClick={handleSave}>Submit</Button>
        </div>
      </div>

      {/* Sub-modals */}
      <AssetsModal
        open={assetsModalOpen}
        onOpenChange={setAssetsModalOpen}
        threatModelId={threatModelId}
        blueprints={blueprints}
        selectedBlueprintId={activeBlueprintId}
      />

      <OutOfScopeModal
        open={outOfScopeModalOpen}
        onOpenChange={setOutOfScopeModalOpen}
        threatModelId={threatModelId}
        blueprints={blueprints}
        selectedBlueprintId={activeBlueprintId}
      />
    </>
  )
}

function ContextButton({
  icon: Icon,
  label,
  count,
  onClick,
  active,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  count?: number
  onClick: () => void
  active?: boolean
}) {
  return (
    <Button
      variant="outline"
      className={cn(
        'h-auto py-3 px-4 flex flex-col items-center gap-2 text-center relative',
        active && 'border-amber-500 border-2 bg-amber-50'
      )}
      onClick={onClick}
    >
      <Icon className="h-5 w-5" />
      <span className="text-xs leading-tight">{label}</span>
      {count !== undefined && count > 0 && (
        <span className="absolute -top-2 -right-2 bg-amber-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
          {count}
        </span>
      )}
    </Button>
  )
}
