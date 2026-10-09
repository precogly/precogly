import { expect, test } from '@playwright/test'

/**
 * Smoke test for the signed-in harness: the storage state from
 * e2e/global-setup.ts gets a seeded user past the login wall and the list
 * shows the sample models the seed command creates.
 */
test('a seeded user sees the sample threat models', async ({ page }) => {
  await page.goto('/threat-models')

  await expect(page).not.toHaveURL(/\/login/)
  await expect(page.getByText('Sample AWS Serverless Web App')).toBeVisible({
    timeout: 15_000,
  })
})
