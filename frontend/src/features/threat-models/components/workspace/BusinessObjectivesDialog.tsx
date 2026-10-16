/** The business objectives card (list, add, edit, delete) in a dialog. */

import { BusinessObjectivesCard } from './BusinessObjectivesCard'
import { OverviewCardDialog } from './OverviewCardDialog'

interface BusinessObjectivesDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
}

export function BusinessObjectivesDialog({ open, onOpenChange, threatModelId }: BusinessObjectivesDialogProps) {
  return (
    <OverviewCardDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Business objectives"
      description="Add, edit or delete the business objectives of the model."
    >
      <BusinessObjectivesCard threatModelId={threatModelId} />
    </OverviewCardDialog>
  )
}
