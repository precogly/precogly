/**
 * One section of the Overview: a header row that expands the section in
 * place. Collapsed by default unless the caller says otherwise; `open` and
 * `onOpenChange` make it controlled. Opening a section scrolls it into view,
 * so content that opens below the fold is not left hidden.
 */

import { useRef, type ReactNode } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'

interface OverviewSectionProps {
  title: string
  /** Muted text beside the title, such as a count. */
  summary?: ReactNode
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  /** Buttons on the right of the header row; clicks there do not toggle the section. */
  headerActions?: ReactNode
  testId?: string
  children: ReactNode
}

export function OverviewSection({
  title,
  summary,
  defaultOpen = false,
  open,
  onOpenChange,
  headerActions,
  testId,
  children,
}: OverviewSectionProps) {
  const sectionRef = useRef<HTMLDivElement>(null)
  const handleOpenChange = (nextOpen: boolean) => {
    onOpenChange?.(nextOpen)
    // After the content has rendered: show as much of the section as fits.
    if (nextOpen) requestAnimationFrame(() => sectionRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }))
  }
  return (
    <Collapsible
      ref={sectionRef}
      defaultOpen={defaultOpen}
      open={open}
      onOpenChange={handleOpenChange}
      className="group/section rounded-lg border"
      data-testid={testId}
    >
      <div className="flex items-center gap-3 px-4 py-3">
        <CollapsibleTrigger className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left">
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground group-data-[state=open]/section:hidden" />
          <ChevronDown className="hidden h-4 w-4 shrink-0 text-muted-foreground group-data-[state=open]/section:block" />
          <span className="text-sm font-medium">{title}</span>
          {summary && <span className="truncate text-xs text-muted-foreground">{summary}</span>}
        </CollapsibleTrigger>
        {headerActions && <div className="flex shrink-0 items-center gap-2">{headerActions}</div>}
      </div>
      <CollapsibleContent className="border-t px-4 py-4">{children}</CollapsibleContent>
    </Collapsible>
  )
}
