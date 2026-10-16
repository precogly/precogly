import { ApiError } from '@/lib/api'

/** The message of a failed write, for the toast: the 403 on platform status names the role. */
export function writeErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'Only the Security Team can set or remove platform status.'
    if (error.data && typeof error.data === 'object') {
      const detail = (error.data as { detail?: unknown }).detail
      if (typeof detail === 'string') return detail
      const firstValue = Object.values(error.data as Record<string, unknown>)[0]
      if (typeof firstValue === 'string') return firstValue
      if (Array.isArray(firstValue) && typeof firstValue[0] === 'string') return firstValue[0]
    }
  }
  return fallback
}
