import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Label } from '@/components/ui/label'

/**
 * The collapsed "Advanced" section of a side panel (plan 11.11, tier
 * "Advanced"). Closed by default; the fields inside are the ones most users
 * never need.
 */
export function AdvancedSection({
  title = 'Advanced',
  defaultOpen = false,
  children,
}: {
  title?: string
  defaultOpen?: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="space-y-2" data-testid="advanced-section">
      <button
        type="button"
        className="flex items-center gap-2 w-full text-left"
        onClick={() => setOpen((previous) => !previous)}
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
        <Label className="cursor-pointer">{title}</Label>
      </button>
      {open && <div className="space-y-3 pl-6">{children}</div>}
    </div>
  )
}
