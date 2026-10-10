import { toast } from 'sonner'
import { api } from '@/lib/api'

/**
 * Warnings from a DELETE. The backend answers 204 (no body) normally, or 200
 * with `{"warnings": [...]}` when the delete removed the last target of a
 * scoped control. Anything unreadable counts as none.
 */
export function parseDeleteWarnings(body: unknown): string[] {
  if (typeof body !== 'object' || body === null) return []
  const warnings = (body as { warnings?: unknown }).warnings
  return Array.isArray(warnings)
    ? warnings.filter((item): item is string => typeof item === 'string')
    : []
}

/** DELETE an endpoint and return the warnings the backend sent (empty on 204). */
export async function deleteWithWarnings(endpoint: string): Promise<string[]> {
  return parseDeleteWarnings(await api.delete<unknown>(endpoint))
}

/** Show delete warnings in one toast; does nothing when there are none. */
export function showDeleteWarnings(warnings: string[]): void {
  if (warnings.length === 0) return
  toast.warning('Some controls changed scope', {
    description: warnings.join('\n'),
  })
}
