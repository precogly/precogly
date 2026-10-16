/** The use cases card (list, add, edit, delete) in a dialog. */

import { OverviewCardDialog } from './OverviewCardDialog'
import { UseCasesCard } from './UseCasesCard'

interface UseCasesDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  threatModelId: string
}

export function UseCasesDialog({ open, onOpenChange, threatModelId }: UseCasesDialogProps) {
  return (
    <OverviewCardDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Use cases"
      description="Add, edit or delete the use cases of the model."
    >
      <UseCasesCard threatModelId={threatModelId} />
    </OverviewCardDialog>
  )
}
