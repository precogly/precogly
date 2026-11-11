/**
 * API client with authentication support.
 *
 * Handles JWT token management and provides typed fetch wrapper.
 */

export const API_BASE = '/api'

// Token storage keys
const TOKEN_KEY = 'precogly_access_token'
const REFRESH_TOKEN_KEY = 'precogly_refresh_token'

// Token management
export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

export function setTokens(access: string, refresh: string): void {
  localStorage.setItem(TOKEN_KEY, access)
  localStorage.setItem(REFRESH_TOKEN_KEY, refresh)
}

export function clearTokens(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
  // Clear Django session cookies that may have been set
  document.cookie = 'sessionid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;'
  document.cookie = 'csrftoken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;'
}

export function isAuthenticated(): boolean {
  return !!getAccessToken()
}

// API Error class
export class ApiError extends Error {
  status: number
  data?: unknown

  constructor(message: string, status: number, data?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

// Refresh token if expired
async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return null

  try {
    const response = await fetch(`${API_BASE}/auth/token/refresh/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: refreshToken }),
    })

    if (!response.ok) {
      clearTokens()
      return null
    }

    const data = await response.json()
    localStorage.setItem(TOKEN_KEY, data.access)
    return data.access
  } catch {
    clearTokens()
    return null
  }
}

// Main fetch wrapper with auth
export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = endpoint.startsWith('/') ? `${API_BASE}${endpoint}` : `${API_BASE}/${endpoint}`

  // Build headers
  const headers = new Headers(options.headers)
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json')
  }

  // Add auth token if available
  const token = getAccessToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  // Make request
  let response = await fetch(url, { ...options, headers })

  // If 401, try to refresh token and retry
  if (response.status === 401 && token) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      headers.set('Authorization', `Bearer ${newToken}`)
      response = await fetch(url, { ...options, headers })
    }
  }

  // Handle errors
  if (!response.ok) {
    let errorData: unknown
    try {
      errorData = await response.json()
    } catch {
      errorData = await response.text()
    }
    throw new ApiError(
      `API Error: ${response.status} ${response.statusText}`,
      response.status,
      errorData
    )
  }

  // Return JSON or empty object for 204
  if (response.status === 204) {
    return {} as T
  }

  return response.json()
}

// Convenience methods
export const api = {
  get: <T>(endpoint: string) => apiFetch<T>(endpoint),

  post: <T>(endpoint: string, data?: unknown) =>
    apiFetch<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    }),

  patch: <T>(endpoint: string, data: unknown) =>
    apiFetch<T>(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  put: <T>(endpoint: string, data: unknown) =>
    apiFetch<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: <T>(endpoint: string) =>
    apiFetch<T>(endpoint, { method: 'DELETE' }),

  uploadFile: async <T>(
    endpoint: string,
    file: File,
    additionalData?: Record<string, string>,
    fieldName: string = 'image'
  ): Promise<T> => {
    const formData = new FormData()
    formData.append(fieldName, file)
    formData.append('filename', file.name)

    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, value)
      })
    }

    const url = endpoint.startsWith('/') ? `${API_BASE}${endpoint}` : `${API_BASE}/${endpoint}`

    // Build headers (don't set Content-Type - browser sets it with boundary for FormData)
    const headers = new Headers()
    const token = getAccessToken()
    if (token) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    // Make request
    let response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    })

    // If 401, try to refresh token and retry
    if (response.status === 401 && token) {
      const newToken = await refreshAccessToken()
      if (newToken) {
        headers.set('Authorization', `Bearer ${newToken}`)
        response = await fetch(url, {
          method: 'POST',
          headers,
          body: formData,
        })
      }
    }

    // Handle errors
    if (!response.ok) {
      let errorData: unknown
      try {
        errorData = await response.json()
      } catch {
        errorData = await response.text()
      }
      throw new ApiError(
        `API Error: ${response.status} ${response.statusText}`,
        response.status,
        errorData
      )
    }

    return response.json()
  },
}

// Paginated list endpoints

/** One page of a DRF `PageNumberPagination` response. */
export interface Page<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

/**
 * Fetch one page of a list endpoint.
 *
 * List endpoints are paginated by default, but a viewset may set
 * `pagination_class = None` and return a bare array — many do. Both shapes come
 * back as a `Page` so callers never branch: a bare array is reported as a single
 * page holding everything.
 *
 * `pageSize` is capped server-side by `ClientSizedPagination.max_page_size`;
 * asking for more silently yields the cap rather than erroring.
 */
export async function getPage<T>(
  endpoint: string,
  params: { page?: number; pageSize?: number } = {}
): Promise<Page<T>> {
  const query = new URLSearchParams()
  if (params.page !== undefined) query.set('page', String(params.page))
  // Snake case deliberately. The camelCase parser rewrites request bodies and
  // leaves query strings alone, so DRF reads this key verbatim as `page_size`.
  if (params.pageSize !== undefined) query.set('page_size', String(params.pageSize))

  const separator = endpoint.includes('?') ? '&' : '?'
  const url = query.size > 0 ? `${endpoint}${separator}${query}` : endpoint

  const response = await apiFetch<Page<T> | T[]>(url)
  if (Array.isArray(response)) {
    return { count: response.length, next: null, previous: null, results: response }
  }
  return response
}

// Auth API
export interface LoginCredentials {
  email: string
  password: string
}

export interface LoginResponse {
  access: string
  refresh: string
  user: {
    pk: number
    email: string
  }
}

export interface RegisterInput {
  email: string
  password1: string
  password2: string
}

export async function login(credentials: LoginCredentials): Promise<LoginResponse> {
  // Clear any stale session/CSRF cookies before login to prevent CSRF validation
  // errors when Django's SessionAuthentication sees an expired sessionid cookie
  clearTokens()

  const response = await fetch(`${API_BASE}/auth/login/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new ApiError('Login failed', response.status, error)
  }

  const data = await response.json()
  setTokens(data.access, data.refresh)
  return data
}

export async function register(input: RegisterInput): Promise<LoginResponse> {
  // Clear any stale session/CSRF cookies before registration
  clearTokens()

  // dj-rest-auth requires username field - use email as username
  const payload = {
    username: input.email,
    email: input.email,
    password1: input.password1,
    password2: input.password2,
  }

  const response = await fetch(`${API_BASE}/auth/registration/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new ApiError('Registration failed', response.status, error)
  }

  const data = await response.json()
  setTokens(data.access, data.refresh)
  return data
}

export async function logout(): Promise<void> {
  try {
    await apiFetch('/auth/logout/', { method: 'POST' })
  } finally {
    clearTokens()
  }
}

export async function getCurrentUser() {
  return apiFetch<{ pk: number; email: string }>('/auth/user/')
}
