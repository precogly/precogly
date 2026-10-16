/**
 * A dialog that holds one of the Overview's cards unchanged. The card keeps
 * its own title and actions; the dialog drops the card's border and shadow
 * and leaves room for its close button.
 */

import type { ReactNode } from 'react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'

interface OverviewCardDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Read by screen readers; the card shows its own visible title. */
  title: string
  description: string
  children: ReactNode
}

export function OverviewCardDialog({ open, onOpenChange, title, description, children }: OverviewCardDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="gap-0 p-0 sm:max-w-3xl [&>[data-slot=card]]:border-0 [&>[data-slot=card]]:shadow-none [&_[data-slot=card-header]]:pr-12">
        <DialogTitle className="sr-only">{title}</DialogTitle>
        <DialogDescription className="sr-only">{description}</DialogDescription>
        {children}
      </DialogContent>
    </Dialog>
  )
}
