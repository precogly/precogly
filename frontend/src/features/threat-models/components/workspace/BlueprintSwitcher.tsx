/**
 * The blueprint switcher in the model header (plan J2).
 *
 * With one blueprint nothing changes on the page: "Add blueprint" and
 * "Manage blueprints" sit in a small menu. With more than one, the switcher
 * shows the selected blueprint and lists the others.
 */

import { ChevronDown, Layers, MoreHorizontal, Plus, Settings2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { Blueprint } from '@/features/threat-models/types/core'
import { showsBlueprintChoice, sortBlueprints } from './blueprint-utils'

interface BlueprintSwitcherProps {
  blueprints: Blueprint[]
  selectedBlueprintId: number | null
  onSelect: (blueprintId: number) => void
  onAddBlueprint: () => void
  onManageBlueprints: () => void
}

export function BlueprintSwitcher({
  blueprints,
  selectedBlueprintId,
  onSelect,
  onAddBlueprint,
  onManageBlueprints,
}: BlueprintSwitcherProps) {
  const ordered = sortBlueprints(blueprints)
  const selected = ordered.find((blueprint) => blueprint.id === selectedBlueprintId) ?? ordered[0]

  const menuItems = (
    <>
      <DropdownMenuItem onClick={onAddBlueprint} className="text-xs gap-2">
        <Plus className="h-3 w-3" />
        Add blueprint
      </DropdownMenuItem>
      <DropdownMenuItem onClick={onManageBlueprints} className="text-xs gap-2">
        <Settings2 className="h-3 w-3" />
        Manage blueprints...
      </DropdownMenuItem>
    </>
  )

  if (!showsBlueprintChoice(blueprints)) {
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" aria-label="More actions">
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">{menuItems}</DropdownMenuContent>
      </DropdownMenu>
    )
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-7 gap-1 px-2 text-xs" data-testid="blueprint-switcher">
          <Layers className="h-3 w-3" />
          <span className="text-muted-foreground">Blueprint:</span>
          <span className="max-w-[200px] truncate">{selected?.name ?? 'None'}</span>
          <ChevronDown className="h-3 w-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[220px]">
        <DropdownMenuLabel className="text-xs">Blueprints</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={selected ? String(selected.id) : ''}
          onValueChange={(value) => onSelect(Number(value))}
        >
          {ordered.map((blueprint) => (
            <DropdownMenuRadioItem key={blueprint.id} value={String(blueprint.id)} className="text-xs">
              {blueprint.name}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        {menuItems}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
