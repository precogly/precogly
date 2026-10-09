/**
 * One row of the analysis tree (plan 11.3): System, blueprint, zone,
 * component, flow, boundary, or a Flows or Boundaries group. Counts come
 * from the tree builder, where each scenario counts once per level.
 */

import { createElement } from 'react'
import {
  Boxes,
  Building2,
  ChevronRight,
  Cog,
  Database,
  Layers,
  MoveRight,
  Shield,
  SquareDashed,
  Trash2,
  User,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { ZONE_TYPES } from '@/types/domain'
import type { AnalysisTreeNode } from './hierarchy-utils'
import { isSameSelection, type AnalysisSelection } from './analysis-selection'
import { ComponentDataAssetsDisplay } from './ComponentDataAssetsDisplay'
import { DataFlowAssetsDisplay } from './DataFlowAssetsDisplay'

const COMPONENT_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  process: Cog,
  datastore: Database,
  external_human_actor: User,
  external_system_actor: Building2,
}

function rowIcon(node: AnalysisTreeNode): React.ComponentType<{ className?: string }> {
  switch (node.kind) {
    case 'system':
      return Boxes
    case 'blueprint':
      return Layers
    case 'zone':
      return Shield
    case 'flow':
    case 'flowsGroup':
      return MoveRight
    case 'boundary':
    case 'boundariesGroup':
      return SquareDashed
    default:
      return COMPONENT_ICONS[node.category ?? ''] ?? Cog
  }
}

function zoneTypeLabel(node: AnalysisTreeNode): string | null {
  if (node.kind !== 'zone') return null
  return ZONE_TYPES.find((entry) => entry.value === node.zoneType)?.label ?? null
}

interface AnalysisTreeItemProps {
  node: AnalysisTreeNode
  selection: AnalysisSelection | null
  collapsedKeys: Set<string>
  onSelect: (selection: AnalysisSelection) => void
  onToggleCollapsed: (key: string) => void
  onRequestDeleteComponent: (component: { id: number; name: string }) => void
}

export function AnalysisTreeItem({
  node,
  selection,
  collapsedKeys,
  onSelect,
  onToggleCollapsed,
  onRequestDeleteComponent,
}: AnalysisTreeItemProps) {
  const isGroup = node.selection === null
  const isSelected = !isGroup && isSameSelection(node.selection, selection)
  const hasChildren = node.children.length > 0
  const isCollapsed = collapsedKeys.has(node.key)
  const { counts } = node
  const typeLabel = zoneTypeLabel(node)

  const select = () => {
    if (node.selection) onSelect(node.selection)
    else if (hasChildren) onToggleCollapsed(node.key)
  }

  return (
    <>
      <div
        role="button"
        tabIndex={0}
        data-tree-key={node.key}
        onClick={select}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            select()
          }
        }}
        className={cn(
          'group w-full cursor-pointer rounded-md p-1.5 text-left transition-colors',
          isSelected ? 'border border-slate-300 bg-slate-100' : 'hover:bg-slate-50',
          isGroup && 'mt-1'
        )}
        style={{ paddingLeft: `${6 + node.depth * 14}px` }}
      >
        <div className="flex items-center justify-between gap-1">
          <div className="flex min-w-0 items-center gap-1.5">
            {hasChildren ? (
              <button
                type="button"
                className="shrink-0 rounded p-0.5 transition-colors hover:bg-slate-200"
                onClick={(event) => {
                  event.stopPropagation()
                  onToggleCollapsed(node.key)
                }}
                aria-label={isCollapsed ? `Expand ${node.label}` : `Collapse ${node.label}`}
              >
                <ChevronRight
                  className={cn('h-3 w-3 text-muted-foreground transition-transform', !isCollapsed && 'rotate-90')}
                />
              </button>
            ) : (
              <span className="w-4 shrink-0" />
            )}
            {createElement(rowIcon(node), { className: 'h-4 w-4 shrink-0 text-muted-foreground' })}
            <div className="min-w-0">
              <div className={cn('truncate text-sm', isGroup ? 'text-xs font-medium text-muted-foreground' : 'font-medium')}>
                {node.label}
                {typeLabel && (
                  <Badge variant="outline" className="ml-1.5 px-1 py-0 text-[10px] font-normal">
                    {typeLabel}
                  </Badge>
                )}
              </div>
              {(node.secondaryLabel || (node.kind === 'zone' && node.trustLevel != null)) && (
                <div className="truncate text-xs text-muted-foreground">
                  {node.secondaryLabel}
                  {node.kind === 'zone' && node.trustLevel != null && `TL ${node.trustLevel}`}
                </div>
              )}
            </div>
          </div>
          <div className="ml-1 flex shrink-0 items-center gap-1">
            {node.kind === 'component' && node.backendId !== undefined && node.isAnalysisOnly && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100 touch:opacity-100"
                onClick={(event) => {
                  event.stopPropagation()
                  onRequestDeleteComponent({ id: node.backendId!, name: node.label })
                }}
                aria-label={`Delete ${node.label}`}
                title="Delete component"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            )}
            {node.kind === 'component' && node.backendId !== undefined && !node.isAnalysisOnly && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="opacity-0 transition-opacity group-hover:opacity-100 touch:opacity-100">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="pointer-events-none h-7 w-7 text-muted-foreground opacity-50"
                      disabled
                      aria-label={`Cannot delete ${node.label}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent side="left">
                  This component is on a diagram. Delete it where you drew it.
                </TooltipContent>
              </Tooltip>
            )}
            {counts.exposed > 0 ? (
              <Badge variant="outline" className="shrink-0 bg-red-100 text-xs text-red-700" title={`${counts.total} threats`}>
                {counts.exposed} exposed
              </Badge>
            ) : counts.addressable > 0 ? (
              <Badge variant="outline" className="shrink-0 bg-yellow-100 text-xs text-yellow-700" title={`${counts.total} threats`}>
                {counts.addressable} in progress
              </Badge>
            ) : null}
            {counts.total > 0 && (
              <span className="text-xs tabular-nums text-muted-foreground" title="Threats, each counted once">
                ({counts.total})
              </span>
            )}
          </div>
        </div>
      </div>
      {isSelected && node.kind === 'component' && <ComponentDataAssetsDisplay componentId={node.backendId} />}
      {isSelected && node.kind === 'flow' && <DataFlowAssetsDisplay dataFlowId={node.backendId} />}
      {hasChildren &&
        !isCollapsed &&
        node.children.map((child) => (
          <AnalysisTreeItem
            key={child.key}
            node={child}
            selection={selection}
            collapsedKeys={collapsedKeys}
            onSelect={onSelect}
            onToggleCollapsed={onToggleCollapsed}
            onRequestDeleteComponent={onRequestDeleteComponent}
          />
        ))}
    </>
  )
}
