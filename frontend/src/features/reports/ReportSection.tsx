import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

/** One report section; collapsed to its title until clicked, so a report opens as a list of sections. */

interface ReportSectionProps {
  title: string
  defaultOpen?: boolean
  children: React.ReactNode
}

export function ReportSection({ title, defaultOpen = false, children }: ReportSectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border rounded-lg">
      <button
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        className="w-full flex items-center gap-2 px-4 py-3 text-left font-semibold hover:bg-muted/50 transition-colors"
      >
        {isOpen ? (
          <ChevronDown className="h-4 w-4 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0" />
        )}
        {title}
      </button>
      {isOpen && <div className="px-4 pb-4">{children}</div>}
    </div>
  )
}
