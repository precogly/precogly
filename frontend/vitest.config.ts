import path from 'path'
import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    // Playwright owns these (playwright.config.ts `testMatch`); vitest would
    // otherwise collect them and fail on Playwright's `test()`.
    exclude: [...configDefaults.exclude, '**/__tests__/e2e/**/*.spec.ts'],
  },
})
