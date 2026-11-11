/**
 * Clickable taxonomy references (CWE, ATT&CK and so on), shared by
 * TaxonomyBadges and the threat category picker so both open links the same
 * way. Kept out of the components so fast refresh works.
 */
import type { TaxonomyBadgeEntry } from '@/types/domain'

/** Open a taxonomy entry's reference in a new tab, without triggering the row or badge underneath. */
export function openReferenceUrl(url: string, event: React.SyntheticEvent) {
  event.stopPropagation()
  event.preventDefault()
  window.open(url, '_blank', 'noopener,noreferrer')
}

/** Props that make a badge open the entry's reference in a new tab, or nothing when it has none. */
export function referenceLinkProps(entry: Pick<TaxonomyBadgeEntry, 'referenceUrl'>) {
  if (!entry.referenceUrl) return {}
  const referenceUrl = entry.referenceUrl
  return {
    role: 'link' as const,
    tabIndex: 0,
    onClick: (event: React.SyntheticEvent) => openReferenceUrl(referenceUrl, event),
    onKeyDown: (event: React.KeyboardEvent) => {
      if (event.key === 'Enter' || event.key === ' ') openReferenceUrl(referenceUrl, event)
    },
  }
}
