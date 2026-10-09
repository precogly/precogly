import { FileText, Users, Package } from 'lucide-react'

/**
 * The quick links beside the completion card. The primary system is chosen
 * in the Details card (plan J1), so there is no systems dialog here.
 */
interface RelationshipCardsProps {
  onManageThreatModels: () => void
  onManagePacks: () => void
  onManagePeople: () => void
}

export function RelationshipCards({
  onManageThreatModels,
  onManagePacks,
  onManagePeople,
}: RelationshipCardsProps) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <button
        onClick={onManageThreatModels}
        className="flex items-center gap-3 rounded-lg border px-4 py-3 text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
      >
        <FileText className="h-4 w-4 shrink-0" />
        Related Models
      </button>
      <button
        onClick={onManagePacks}
        className="flex items-center gap-3 rounded-lg border px-4 py-3 text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
      >
        <Package className="h-4 w-4 shrink-0" />
        Manage Connected Library Packs
      </button>
      <button
        onClick={onManagePeople}
        className="flex items-center gap-3 rounded-lg border px-4 py-3 text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
      >
        <Users className="h-4 w-4 shrink-0" />
        Manage Team Members
      </button>
    </div>
  )
}
