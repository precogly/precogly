import { useState, useCallback, useMemo } from 'react'
import type { XYPosition } from '@xyflow/react'
import { User, Server, Cog, Database, Shield, Box, StickyNote, ChevronRight, ChevronDown, Search, X, Package, ShieldCheck, ArrowUp } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import type { DiagramNodeType } from '../../types'
import type { DFDNotationStyle } from '../../types/notation'
import { useGroupedComponentLibrary, categoryToNodeType } from '../../api/component-library'
import type { ComponentLibraryItem } from '../../api/component-library'
import { useCreateNode } from '../../hooks/useCreateNode'

interface ComponentPanelProps {
  threatModelId?: string
  onClose: () => void
  connectionMode?: boolean
  onConnectionModeChange?: (enabled: boolean) => void
  boundaryMode?: boolean
  onBoundaryModeChange?: (enabled: boolean) => void
  getCanvasCenterPosition?: () => XYPosition
  notationStyle?: DFDNotationStyle
}

interface DfdTypeItem {
  type: DiagramNodeType
  label: string
  icon: React.ComponentType<{ className?: string }>
  color: string
}

const dfdTypes: DfdTypeItem[] = [
  { type: 'humanActor', label: 'Human Actor', icon: User, color: 'text-green-600' },
  { type: 'systemActor', label: 'System Actor', icon: Server, color: 'text-slate-600' },
  { type: 'process', label: 'Process', icon: Cog, color: 'text-blue-600' },
  { type: 'datastore', label: 'Data Store', icon: Database, color: 'text-purple-600' },
  { type: 'trustZone', label: 'Trust Zone', icon: Shield, color: 'text-orange-600' },
  { type: 'systemScope', label: 'System Scope', icon: Box, color: 'text-gray-600' },
  { type: 'stickyNote', label: 'Sticky Note', icon: StickyNote, color: 'text-amber-700' },
]

const categoryIcons: Record<string, { icon: React.ComponentType<{ className?: string }>; color: string }> = {
  process: { icon: Cog, color: 'text-blue-600' },
  datastore: { icon: Database, color: 'text-purple-600' },
  external_human_actor: { icon: User, color: 'text-green-600' },
  external_system_actor: { icon: Server, color: 'text-slate-600' },
}

function handleDfdTypeDragStart(event: React.DragEvent, nodeType: DiagramNodeType) {
  event.dataTransfer.setData('application/reactflow-node-type', nodeType)
  event.dataTransfer.effectAllowed = 'move'
}

function handleComponentDragStart(event: React.DragEvent, item: ComponentLibraryItem) {
  const nodeType = categoryToNodeType(item.category)
  event.dataTransfer.setData('application/reactflow-node-type', nodeType)
  event.dataTransfer.setData('application/reactflow-component-ref', item.slug || item.qualifiedSlug || '')
  event.dataTransfer.setData('application/reactflow-component-name', item.name)
  event.dataTransfer.effectAllowed = 'move'
}

function CollapsibleSection({
  title,
  icon,
  defaultOpen = true,
  children,
}: {
  title: string
  icon?: React.ReactNode
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div>
      <button
        type="button"
        className="flex items-center gap-1.5 w-full px-3 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wider hover:bg-muted/50"
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {icon}
        <span className="truncate">{title}</span>
      </button>
      {open && <div className="pb-1">{children}</div>}
    </div>
  )
}

export function ComponentPanel({
  threatModelId,
  onClose,
  connectionMode = false,
  onConnectionModeChange,
  boundaryMode = false,
  onBoundaryModeChange,
  getCanvasCenterPosition,
  notationStyle = 'dfd3',
}: ComponentPanelProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const { groups, isLoading } = useGroupedComponentLibrary(threatModelId)
  const { createNode } = useCreateNode(notationStyle)
  const normalizedQuery = searchQuery.toLowerCase().trim()
  const showLibrary = !!threatModelId

  const filteredDfdTypes = useMemo(() => {
    if (!normalizedQuery) return dfdTypes
    return dfdTypes.filter((item) => item.label.toLowerCase().includes(normalizedQuery))
  }, [normalizedQuery])

  const showTrustBoundary = !normalizedQuery || 'trust boundary'.includes(normalizedQuery)
  const showFlow = !normalizedQuery || 'flow'.includes(normalizedQuery)

  const filteredGroups = useMemo(() => {
    if (!normalizedQuery) return groups
    return groups
      .map((group) => ({
        ...group,
        components: group.components.filter((c) =>
          c.name.toLowerCase().includes(normalizedQuery) ||
          c.provider.toLowerCase().includes(normalizedQuery)
        ),
      }))
      .filter((group) => group.components.length > 0)
  }, [groups, normalizedQuery])

  const handleClearSearch = useCallback(() => setSearchQuery(''), [])

  const handleClickToPlace = useCallback(
    (type: DiagramNodeType) => {
      if (!getCanvasCenterPosition) return
      const center = getCanvasCenterPosition()
      createNode(type, center)
    },
    [createNode, getCanvasCenterPosition]
  )

  return (
    <div className="w-64 bg-background border-r h-full flex flex-col">
      <div className="flex items-center justify-between px-3 py-2 border-b">
        <span className="text-sm font-semibold">Components</span>
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </div>

      {showLibrary && (
        <div className="px-3 py-2">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search components..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-7 h-8 text-sm"
            />
            {searchQuery && (
              <button
                type="button"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                onClick={handleClearSearch}
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>
      )}

      <ScrollArea className="flex-1">
        <div className="pb-4">
          {(filteredDfdTypes.length > 0 || showTrustBoundary || showFlow) && (
            <CollapsibleSection title="Threat Modeling" icon={<Shield className="h-3 w-3" />}>
              {filteredDfdTypes.map((item) => (
                <div
                  key={item.type}
                  draggable
                  onDragStart={(e) => handleDfdTypeDragStart(e, item.type)}
                  onClick={() => handleClickToPlace(item.type)}
                  className="flex items-center gap-2 px-4 py-1.5 cursor-grab active:cursor-grabbing hover:bg-muted/50 text-sm select-none"
                >
                  <item.icon className={`h-4 w-4 flex-shrink-0 ${item.color}`} />
                  <span className="truncate">{item.label}</span>
                </div>
              ))}
              {showTrustBoundary && onBoundaryModeChange && (
                <div
                  onClick={() => onBoundaryModeChange(!boundaryMode)}
                  className={cn(
                    'flex items-center gap-2 px-4 py-1.5 cursor-pointer text-sm select-none',
                    boundaryMode ? 'bg-primary text-primary-foreground' : 'text-amber-700 hover:bg-muted/50'
                  )}
                >
                  <ShieldCheck className="h-4 w-4 flex-shrink-0" />
                  <span className="truncate">Trust Boundary</span>
                </div>
              )}
              {showFlow && onConnectionModeChange && (
                <div
                  onClick={() => onConnectionModeChange(!connectionMode)}
                  className={cn(
                    'flex items-center gap-2 px-4 py-1.5 cursor-pointer text-sm select-none',
                    connectionMode ? 'bg-primary text-primary-foreground' : 'hover:bg-muted/50'
                  )}
                >
                  <ArrowUp className="h-4 w-4 flex-shrink-0" />
                  <span className="truncate">Flow</span>
                </div>
              )}
            </CollapsibleSection>
          )}

          {showLibrary && isLoading && (
            <div className="px-4 py-3 text-xs text-muted-foreground">Loading libraries...</div>
          )}

          {showLibrary && filteredGroups.map((group) => (
            <CollapsibleSection
              key={group.packSlug}
              title={group.packName}
              icon={<Package className="h-3 w-3" />}
              defaultOpen={!!normalizedQuery}
            >
              {group.components.map((item) => {
                const iconConfig = categoryIcons[item.category]
                const FallbackIcon = iconConfig?.icon || Cog
                const iconColor = iconConfig?.color || 'text-muted-foreground'

                return (
                  <div
                    key={item.qualifiedSlug || item.slug}
                    draggable
                    onDragStart={(e) => handleComponentDragStart(e, item)}
                    className="flex items-center gap-2 px-4 py-1.5 cursor-grab active:cursor-grabbing hover:bg-muted/50 text-sm select-none"
                  >
                    {item.iconSvg ? (
                      <span
                        className="h-4 w-4 flex-shrink-0 [&>svg]:h-full [&>svg]:w-full"
                        dangerouslySetInnerHTML={{ __html: item.iconSvg }}
                      />
                    ) : (
                      <FallbackIcon className={`h-4 w-4 flex-shrink-0 ${iconColor}`} />
                    )}
                    <span className="truncate">{item.name}</span>
                  </div>
                )
              })}
            </CollapsibleSection>
          ))}

          {showLibrary && !isLoading && groups.length === 0 && (
            <div className="px-4 py-3 text-xs text-muted-foreground">
              Connect component packs in Libraries to see components here.
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
