/** The selection logic of the threat sources picker, kept apart so it can be tested. */

export function threatSourceIdsFromThreat(threatSources: { id: number }[] | undefined): number[] {
  return (threatSources ?? []).map((source) => source.id)
}

/** The ids after switching one source on or off; each id appears once. */
export function toggleThreatSourceId(selectedIds: number[], sourceId: number, checked: boolean): number[] {
  const withoutSource = selectedIds.filter((selectedId) => selectedId !== sourceId)
  return checked ? [...withoutSource, sourceId] : withoutSource
}
