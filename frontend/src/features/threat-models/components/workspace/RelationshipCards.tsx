import { FileText, Layers, Users, Package } from 'lucide-react'
import { countLabel } from './overview-utils'

/**
 * The Connections section of the Overview: related models, library packs,
 * team members and blueprints. The primary system is chosen in System
 * Details (plan J1), so there is no systems dialog here. Blueprints replaced
 * "Manage Connected Systems" (renamed, not removed), so its card says so.
 */
interface RelationshipCardsProps {
  blueprintCount: number
  onManageThreatModels: () => void
  onManagePacks: () => void
  onManagePeople: () => void
  onManageBlueprints: () => void
}

const CARD_CLASS_NAME =
  'flex items-center gap-3 rounded-lg border px-4 py-3 text-left text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors'

export function RelationshipCards({
  blueprintCount,
  onManageThreatModels,
  onManagePacks,
  onManagePeople,
  onManageBlueprints,
}: RelationshipCardsProps) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <button onClick={onManageThreatModels} className={CARD_CLASS_NAME}>
        <FileText className="h-4 w-4 shrink-0" />
        Related Models
      </button>
      <button onClick={onManagePacks} className={CARD_CLASS_NAME}>
        <Package className="h-4 w-4 shrink-0" />
        Manage Connected Library Packs
      </button>
      <button onClick={onManagePeople} className={CARD_CLASS_NAME}>
        <Users className="h-4 w-4 shrink-0" />
        Manage Team Members
      </button>
      <button onClick={onManageBlueprints} className={CARD_CLASS_NAME} data-testid="blueprints-card">
        <Layers className="h-4 w-4 shrink-0" />
        <span className="min-w-0">
          <span className="block">Blueprints</span>
          <span className="block text-xs">{countLabel(blueprintCount, 'blueprint')}, formerly Connected Systems</span>
        </span>
      </button>
    </div>
  )
}
