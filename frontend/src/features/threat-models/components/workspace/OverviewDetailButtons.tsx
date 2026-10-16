/**
 * The three buttons of the Overview: System (System Details and System
 * context merged, one dialog with two tabs), Business objectives and Use
 * cases. Each shows a small count or state and opens a dialog; the Overview
 * shows no form fields itself.
 */

import type { ReactNode } from 'react'
import { BookOpen, Server, Target } from 'lucide-react'
import { useAssumptions, useBusinessObjectives, useUseCases } from '@/features/threat-models/api/threat-models'
import { useDataAssets } from '@/features/threat-models/api/data-assets'
import { useOutOfScopeItems } from '@/features/threat-models/api/out-of-scope-items'
import type { ThreatModel } from '@/features/threat-models/types/core'
import { listSummary, systemContextSummary, systemSummary } from './overview-utils'

interface OverviewDetailButtonsProps {
  threatModel: ThreatModel
  onOpenSystem: () => void
  onOpenBusinessObjectives: () => void
  onOpenUseCases: () => void
}

function DetailButton({
  icon,
  label,
  summary,
  onClick,
}: {
  icon: ReactNode
  label: string
  summary: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex min-w-0 cursor-pointer items-center gap-3 rounded-lg border px-4 py-3 text-left transition-colors hover:bg-muted"
    >
      <span className="shrink-0 text-muted-foreground">{icon}</span>
      <span className="min-w-0">
        <span className="block text-sm font-medium">{label}</span>
        <span className="block truncate text-xs text-muted-foreground">{summary}</span>
      </span>
    </button>
  )
}

export function OverviewDetailButtons({
  threatModel,
  onOpenSystem,
  onOpenBusinessObjectives,
  onOpenUseCases,
}: OverviewDetailButtonsProps) {
  const threatModelId = threatModel.id
  const { data: objectives = [] } = useBusinessObjectives(threatModelId)
  const { data: useCases = [] } = useUseCases(threatModelId)
  const { data: assumptions = [] } = useAssumptions(threatModelId)
  const { data: outOfScopeItems = [] } = useOutOfScopeItems(threatModelId)
  const { data: dataAssets = [] } = useDataAssets(threatModelId)

  const criticality = threatModel.criticality
  const contextSummary = systemContextSummary({
    assumptions: assumptions.length,
    unverifiedAssumptions: assumptions.filter((assumption) => assumption.validity !== 'verified').length,
    outOfScopeItems: outOfScopeItems.length,
    dataAssets: dataAssets.length,
  })

  return (
    <div className="grid gap-3 sm:grid-cols-3" data-testid="overview-detail-buttons">
      <DetailButton
        icon={<Server className="h-4 w-4" />}
        label="System"
        summary={systemSummary({
          criticality,
          description: threatModel.description,
          primarySystemId: threatModel.primarySystem,
          contextSummary,
        })}
        onClick={onOpenSystem}
      />
      <DetailButton
        icon={<Target className="h-4 w-4" />}
        label="Business objectives"
        summary={listSummary(objectives.length, 'objective')}
        onClick={onOpenBusinessObjectives}
      />
      <DetailButton
        icon={<BookOpen className="h-4 w-4" />}
        label="Use cases"
        summary={listSummary(useCases.length, 'use case')}
        onClick={onOpenUseCases}
      />
    </div>
  )
}
