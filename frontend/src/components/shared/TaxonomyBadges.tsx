import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  type TaxonomyBadgeEntry,
  formatTaxonomyEntryLabel,
  getTaxonomyEntryColor,
  getTaxonomyEntryBgClass,
} from '@/types/domain'
import { referenceLinkProps } from './taxonomy-reference-link'

interface TaxonomyBadgesProps {
  entries?: TaxonomyBadgeEntry[]
  /** Cap visible badges; overflow shows "+N" with tooltip. 0 = show all. */
  maxVisible?: number
  size?: 'sm' | 'default'
}

export function TaxonomyBadges({ entries, maxVisible = 0, size = 'default' }: TaxonomyBadgesProps) {
  if (!entries || entries.length === 0) return null

  const visibleEntries = maxVisible > 0 ? entries.slice(0, maxVisible) : entries
  const overflowEntries = maxVisible > 0 ? entries.slice(maxVisible) : []
  const textSizeClass = size === 'sm' ? 'text-[10px]' : 'text-xs'

  return (
    <div className="flex flex-wrap items-center gap-1">
      {visibleEntries.map((entry) => {
        const label = formatTaxonomyEntryLabel(entry)
        const bgClass = getTaxonomyEntryBgClass(entry)
        const clickProps = {
          ...referenceLinkProps(entry),
          className: cn(textSizeClass, bgClass, entry.referenceUrl && 'cursor-pointer hover:opacity-80'),
        }

        if (bgClass) {
          // Non-STRIDE: use Tailwind classes
          return (
            <Badge
              key={`${entry.taxonomySlug}-${entry.externalId}`}
              variant="outline"
              title={entry.title}
              {...clickProps}
            >
              {label}
            </Badge>
          )
        }

        // STRIDE: use inline color style
        const color = getTaxonomyEntryColor(entry)
        return (
          <Badge
            key={`${entry.taxonomySlug}-${entry.externalId}`}
            variant="outline"
            title={entry.title}
            style={{ borderColor: color, color }}
            {...clickProps}
          >
            {label}
          </Badge>
        )
      })}

      {overflowEntries.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className={`${textSizeClass} cursor-default`}>
              +{overflowEntries.length}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <div className="space-y-0.5">
              {overflowEntries.map((entry) => (
                <div key={`${entry.taxonomySlug}-${entry.externalId}`} className="text-xs">
                  {formatTaxonomyEntryLabel(entry)}
                </div>
              ))}
            </div>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}
