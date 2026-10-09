import path from 'node:path'
import { defineConfig } from '@playwright/test'

// Written by e2e/global-setup.ts; carries the seeded demo account's JWT pair.
const SIGNED_IN_STORAGE_STATE = path.join(process.cwd(), 'e2e', '.auth', 'signed-in.json')

export default defineConfig({
  testDir: './src',
  testMatch: '**/__tests__/e2e/**/*.spec.ts',
  timeout: 30_000,
  globalSetup: './e2e/global-setup.ts',
  use: {
    baseURL: 'http://localhost:5173',
    headless: true,
    screenshot: 'only-on-failure',
  },
  projects: [
    // Guest-only specs: no backend, no login.
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
      testIgnore: '**/*.signed-in.spec.ts',
    },
    // Specs that drive the signed-in app against the seeded compose stack.
    {
      name: 'signed-in',
      use: { browserName: 'chromium', storageState: SIGNED_IN_STORAGE_STATE },
      testMatch: '**/__tests__/e2e/**/*.signed-in.spec.ts',
    },
  ],
})
