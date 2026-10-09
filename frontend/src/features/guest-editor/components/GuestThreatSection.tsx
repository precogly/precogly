import { useState } from 'react'
import { ChevronDown, ChevronRight, Plus, ShieldAlert, Trash2, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useGuestEditor } from '../context/GuestEditorContext'
import { GuestThreatDialog } from './GuestAddThreatDialog'
import type { GuestTargetRef, GuestThreat } from '../types'
import { LEVEL_COLORS, STATUS_COLORS, getThreatWarning, threatDisplayNumber } from '../types'
import { STRIDE_CONFIG } from '@/types/domain'
import { targetLabel } from '../lib/guest-model'
import { hiddenTargetsNote } from '../lib/guest-targets'

interface GuestThreatSectionProps {
  target: GuestTargetRef
  targetName: string
}

/** The threat list in a side panel: every threat that names this element among its targets. */
export function GuestThreatSection({ target, targetName }: GuestThreatSectionProps) {
  const guestEditor = useGuestEditor()
  const [isOpen, setIsOpen] = useState(true)
  const [showDialog, setShowDialog] = useState(false)
  const [editingThreat, setEditingThreat] = useState<GuestThreat | undefined>(undefined)

  if (!guestEditor) return null

  const threats = guestEditor.getThreatsForTarget(target.id)
  const threatCount = threats.length

  const handleAddNew = () => {
    setEditingThreat(undefined)
    setShowDialog(true)
  }

  const handleEdit = (threat: GuestThreat) => {
    setEditingThreat(threat)
    setShowDialog(true)
  }

  return (
    <div className="space-y-2">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between w-full text-sm font-medium hover:text-foreground text-muted-foreground"
      >
        <div className="flex items-center gap-2">
          {isOpen ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
          <ShieldAlert className="h-4 w-4" />
          <span>Threats</span>
          {threatCount > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-xs">
              {threatCount}
            </Badge>
          )}
        </div>
      </button>

      {isOpen && (
        <div className="space-y-2 pl-6">
          {threats.length === 0 ? (
            <p className="text-xs text-muted-foreground">No threats added yet.</p>
          ) : (
            <div className="space-y-1.5">
              {threats.map((threat) => {
                const countermeasureCount = guestEditor.getCountermeasureCount(threat.id)
                const warning = getThreatWarning(threat, countermeasureCount)
                const otherTargets = threat.targets.filter((candidate) => candidate.id !== target.id)
                const hiddenNote = hiddenTargetsNote(threat.hiddenTargetRefs, threat.hiddenBlueprintTargetCount)
                return (
                  <div
                    key={threat.id}
                    className="flex flex-col gap-1.5 p-2 rounded-md border bg-card text-sm cursor-pointer hover:bg-muted/50"
                    onClick={() => handleEdit(threat)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="font-mono text-xs text-muted-foreground shrink-0">{threatDisplayNumber(threat)}</span>
                        <span className="font-medium leading-snug truncate">{threat.name}</span>
                        {warning && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500" />
                            </TooltipTrigger>
                            <TooltipContent side="top">
                              <p className="text-xs">{warning}</p>
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 shrink-0 text-muted-foreground hover:text-red-600"
                        onClick={(e) => {
                          e.stopPropagation()
                          guestEditor.removeThreat(threat.id)
                        }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                    {threat.description && (
                      <p className="text-xs text-muted-foreground leading-snug line-clamp-2">
                        {threat.description}
                      </p>
                    )}
                    {(otherTargets.length > 0 || hiddenNote) && (
                      <p className="text-xs text-muted-foreground leading-snug">
                        {otherTargets.length > 0 && (
                          <>Also on: {otherTargets.map((candidate) => targetLabel(candidate, guestEditor.nodes, guestEditor.edges)).join(', ')}</>
                        )}
                        {otherTargets.length > 0 && hiddenNote ? '; ' : ''}
                        {hiddenNote}
                      </p>
                    )}
                    <div className="flex flex-wrap items-center gap-1">
                      <Badge
                        variant="secondary"
                        className={cn('shrink-0 text-xs capitalize', STATUS_COLORS[threat.status])}
                      >
                        {threat.status}
                      </Badge>
                      <Badge
                        variant="secondary"
                        className={cn('shrink-0 text-xs capitalize', LEVEL_COLORS[threat.level])}
                      >
                        {threat.level}
                      </Badge>
                      {threat.category && STRIDE_CONFIG[threat.category] && (
                        <Badge
                          variant="outline"
                          className="shrink-0 text-xs border"
                          style={{
                            color: STRIDE_CONFIG[threat.category].color,
                            borderColor: STRIDE_CONFIG[threat.category].color,
                          }}
                        >
                          {STRIDE_CONFIG[threat.category].label}
                        </Badge>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          <Button
            variant="outline"
            size="sm"
            className="w-full gap-1"
            onClick={handleAddNew}
          >
            <Plus className="h-3 w-3" />
            Add Threat
          </Button>
        </div>
      )}

      <GuestThreatDialog
        open={showDialog}
        onOpenChange={setShowDialog}
        initialTarget={target}
        targetName={targetName}
        editThreat={editingThreat}
      />
    </div>
  )
}
