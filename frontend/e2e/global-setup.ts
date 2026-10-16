/**
 * Playwright global setup for the signed-in end-to-end project.
 *
 * Waits for the backend to answer, logs in with the seeded demo account over
 * the API, and writes a storage state that carries the JWT pair in
 * localStorage under the keys `src/lib/api.ts` reads. Specs in the
 * `signed-in` project start every page already authenticated, with no login
 * form in the loop.
 *
 * Runs against the docker compose stack (`docker compose up -d`), which seeds
 * the demo database on start. Override the targets with E2E_API_URL,
 * E2E_EMAIL and E2E_PASSWORD.
 */
import { request, type FullConfig } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

export const SIGNED_IN_STORAGE_STATE = path.join(process.cwd(), 'e2e', '.auth', 'signed-in.json')

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000'
const EMAIL = process.env.E2E_EMAIL ?? 'admin@precogly.dev'
const PASSWORD = process.env.E2E_PASSWORD ?? 'admin123'
const READY_TIMEOUT_MS = 180_000

const ACCESS_TOKEN_KEY = 'precogly_access_token'
const REFRESH_TOKEN_KEY = 'precogly_refresh_token'

async function waitUntilReady(url: string, label: string): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url)
      if (response.ok) return
      lastError = `${response.status} ${response.statusText}`
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000))
  }
  throw new Error(`${label} at ${url} did not become ready: ${lastError}`)
}

export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL = config.projects[0]?.use?.baseURL ?? 'http://localhost:5173'

  await waitUntilReady(`${API_URL}/api/health/`, 'backend')
  await waitUntilReady(baseURL, 'frontend')

  const api = await request.newContext({ baseURL: API_URL })
  const response = await api.post('/api/auth/login/', {
    data: { email: EMAIL, password: PASSWORD },
  })
  if (!response.ok()) {
    throw new Error(
      `login as ${EMAIL} failed with ${response.status()}: ${await response.text()}`,
    )
  }
  const { access, refresh } = (await response.json()) as { access: string; refresh: string }
  await api.dispose()

  fs.mkdirSync(path.dirname(SIGNED_IN_STORAGE_STATE), { recursive: true })
  fs.writeFileSync(
    SIGNED_IN_STORAGE_STATE,
    JSON.stringify(
      {
        cookies: [],
        origins: [
          {
            origin: baseURL,
            localStorage: [
              { name: ACCESS_TOKEN_KEY, value: access },
              { name: REFRESH_TOKEN_KEY, value: refresh },
            ],
          },
        ],
      },
      null,
      2,
    ),
  )
}
