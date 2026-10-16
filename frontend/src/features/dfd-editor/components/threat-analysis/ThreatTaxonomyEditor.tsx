/**
 * The categories of an existing threat, edited with TaxonomyCategoryPicker.
 * Each change is saved at once as instance taxonomy links; the library
 * threat's own categories are shown fixed.
 */
import { useRef } from 'react'
import { toast } from 'sonner'
import type { TaxonomyEntry } from '@/types/domain'
import {
  useCreateInstanceTaxonomyEntry,
  useDeleteInstanceTaxonomyEntry,
  useInstanceTaxonomyEntries,
} from '@/features/threat-models/api/threats'
import { TaxonomyCategoryPicker } from './TaxonomyCategoryPicker'
import { diffTaxonomyLinks } from './taxonomy-picker-utils'

interface ThreatTaxonomyEditorProps {
  threatModelId: string
  threatId: number
  libraryEntries: TaxonomyEntry[]
  disabled?: boolean
}

export function ThreatTaxonomyEditor({
  threatModelId,
  threatId,
  libraryEntries,
  disabled = false,
}: ThreatTaxonomyEditorProps) {
  const { data: instanceLinks = [], isLoading, isFetching } = useInstanceTaxonomyEntries(threatId)
  const createLink = useCreateInstanceTaxonomyEntry()
  const deleteLink = useDeleteInstanceTaxonomyEntry()
  // Also blocks while the links are refetched, so the next click diffs against fresh links
  // (a stale list would create a duplicate or delete a link that is already gone).
  const saving = createLink.isPending || deleteLink.isPending || isFetching
  // Set synchronously, since a second click can land before the next render disables the controls.
  const changeInFlight = useRef(false)

  const handleChange = async (wantedEntryIds: number[]) => {
    if (changeInFlight.current) return
    changeInFlight.current = true
    const { entryIdsToCreate, linkIdsToDelete } = diffTaxonomyLinks(instanceLinks, wantedEntryIds)
    try {
      await Promise.all([
        ...entryIdsToCreate.map((taxonomyEntry) => createLink.mutateAsync({ taxonomyEntry, threat: threatId })),
        ...linkIdsToDelete.map((linkId) => deleteLink.mutateAsync(linkId)),
      ])
    } catch {
      toast.error('Could not save the categories. Try again.')
    } finally {
      changeInFlight.current = false
    }
  }

  return (
    <TaxonomyCategoryPicker
      threatModelId={threatModelId}
      value={instanceLinks.map((link) => link.taxonomyEntry)}
      onChange={handleChange}
      lockedEntries={libraryEntries}
      disabled={disabled || isLoading || saving}
    />
  )
}
