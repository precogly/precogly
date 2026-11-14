import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'

export interface PendingAuthorization {
  clientName: string
  scopes: { name: string; description: string }[]
  redirectUri: string
  loopbackRedirect: boolean
}

export interface Decision {
  allow: boolean
  password?: string
}

const path = (handle: string) => `/oauth/pending-authorizations/${handle}/`

// Reading binds the request to the signed-in user, so the query runs only once the user
// is known; retrying a 404 would only repeat it.
export function usePendingAuthorization(handle: string, enabled: boolean) {
  return useQuery({
    queryKey: ['oauth', 'pending-authorization', handle],
    queryFn: () => api.get<PendingAuthorization>(path(handle)),
    enabled: enabled && !!handle,
    retry: false,
  })
}

export function useDecision(handle: string) {
  return useMutation({
    mutationFn: (decision: Decision) =>
      api.post<{ redirectUrl: string }>(`${path(handle)}decision/`, decision),
  })
}
