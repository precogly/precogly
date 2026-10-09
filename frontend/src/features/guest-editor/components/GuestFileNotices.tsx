import { useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronRight, Info, X } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface GuestFileNoticesProps {
  /** What the last opened file could not be read as it was (plan 11.9: shown, never logged). */
  warnings: string[]
  onDismissWarnings: () => void
  hiddenBlueprintCount: number
  hiddenElementCount: number
}

function plural(count: number, singular: string, pluralForm: string): string {
  return count === 1 ? singular : pluralForm
}

/**
 * The notices under the header: the import warnings panel and the standing
 * notes about content the file carries that this editor does not show (G8).
 */
export function GuestFileNotices({ warnings, onDismissWarnings, hiddenBlueprintCount, hiddenElementCount }: GuestFileNoticesProps) {
  const [expanded, setExpanded] = useState(true)
  const hasWarnings = warnings.length > 0
  if (!hasWarnings && hiddenBlueprintCount === 0 && hiddenElementCount === 0) return null

  return (
    <div className="border-b bg-amber-50 text-amber-900 text-sm" data-testid="guest-file-notices">
      {(hiddenBlueprintCount > 0 || hiddenElementCount > 0) && (
        <div className="flex flex-col gap-1 px-4 py-2 border-b border-amber-200" data-testid="guest-hidden-notice">
          {hiddenBlueprintCount > 0 && (
            <p className="flex items-center gap-2">
              <Info className="h-4 w-4 shrink-0" />
              <span>
                This file has {hiddenBlueprintCount} more {plural(hiddenBlueprintCount, 'blueprint', 'blueprints')}.{' '}
                {plural(hiddenBlueprintCount, 'It is', 'They are')} not shown here and {plural(hiddenBlueprintCount, 'is', 'are')} kept when you save.
              </span>
            </p>
          )}
          {hiddenElementCount > 0 && (
            <p className="flex items-center gap-2">
              <Info className="h-4 w-4 shrink-0" />
              <span>
                {hiddenElementCount} {plural(hiddenElementCount, 'element', 'elements')} of the blueprint{' '}
                {plural(hiddenElementCount, 'is', 'are')} not on the diagram. {plural(hiddenElementCount, 'It is', 'They are')} kept when you save.
              </span>
            </p>
          )}
        </div>
      )}
      {hasWarnings && (
        <div className="px-4 py-2" data-testid="guest-import-warnings">
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="flex items-center gap-2 font-medium"
              onClick={() => setExpanded((previous) => !previous)}
              aria-expanded={expanded}
            >
              {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              <AlertTriangle className="h-4 w-4" />
              Some of this file could not be read as it was ({warnings.length})
            </button>
            <Button variant="ghost" size="icon" className="h-6 w-6 ml-auto" onClick={onDismissWarnings} aria-label="Dismiss file warnings">
              <X className="h-4 w-4" />
            </Button>
          </div>
          {expanded && (
            <ul className="mt-1 pl-6 list-disc space-y-0.5 max-h-40 overflow-y-auto text-xs">
              {warnings.map((warning, index) => (
                <li key={`${index}-${warning.slice(0, 24)}`}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
