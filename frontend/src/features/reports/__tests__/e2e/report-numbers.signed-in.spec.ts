import { expect, test } from '@playwright/test'

/**
 * The report shows threat and countermeasure numbers (plan 11.6, #590):
 * open the sample model's Report tab as the seeded user, pick the Full
 * report, and check that the threat detail table has numbered rows and that
 * the countermeasure detail cites controls by number.
 *
 * Not yet run: the dev database behind the signed-in project is stale, so
 * this spec is written against the seeded "Sample AWS Serverless Web App"
 * and waits for a fresh compose stack.
 */
test('the full report cites threats and controls by number', async ({ page }) => {
  await page.goto('/threat-models')
  await expect(page).not.toHaveURL(/\/login/)
  await page.getByText('Sample AWS Serverless Web App').first().click()

  await page.getByRole('tab', { name: /report/i }).click()
  await expect(page.getByTestId('report-title')).toHaveText('Sample AWS Serverless Web App', { timeout: 15_000 })

  await page.getByRole('combobox', { name: 'Report type' }).click()
  await page.getByRole('option', { name: /^Full Report/ }).click()

  // Sections start collapsed; open the three this test reads.
  const threatDetailHeader = page.getByRole('button', { name: /^Threat Detail/ })
  await expect(threatDetailHeader).toHaveAttribute('aria-expanded', 'false', { timeout: 15_000 })
  await threatDetailHeader.click()
  await page.getByRole('button', { name: /^Countermeasure Detail/ }).click()
  await page.getByRole('button', { name: 'Review and approval' }).click()

  const threatRows = page.getByTestId('report-threat-row')
  await expect(threatRows.first()).toBeVisible({ timeout: 15_000 })
  await expect(threatRows.first().locator('td').first()).toHaveText(/^T\d+$/)

  const countermeasureRows = page.getByTestId('report-countermeasure-row')
  await expect(countermeasureRows.first()).toBeVisible()
  await expect(countermeasureRows.first().locator('td').first()).toHaveText(/^C\d+$/)
  await expect(countermeasureRows.first().locator('td').nth(3)).toHaveText(/T\d+/)

  await expect(page.getByTestId('report-review')).toBeVisible()
})
