import { expect, test } from '@playwright/test'

/**
 * The compliance matrix (idea from PR #561 by JJediny): per framework, one row
 * per requirement with its state, countermeasures and threats. Runs on the
 * seeded "Sample AWS Serverless Web App", whose library controls map to
 * framework requirements.
 */
test('the compliance report shows a requirement-by-control matrix that links into threat analysis', async ({ page }) => {
  await page.goto('/threat-models')
  await page.getByText('Sample AWS Serverless Web App').first().click()
  await page.getByRole('tab', { name: /report/i }).click()
  await expect(page.getByTestId('report-title')).toHaveText('Sample AWS Serverless Web App', { timeout: 15_000 })

  await page.getByRole('combobox', { name: 'Report type' }).click()
  await page.getByRole('option', { name: /^Compliance Report/ }).click()
  const header = page.getByRole('button', { name: 'Compliance Matrix' })
  await expect(header).toHaveAttribute('aria-expanded', 'false')
  await header.click()

  const matrix = page.getByTestId('compliance-matrix')
  await expect(matrix).toBeVisible()
  // Coverage is stated against the installed pack, never the whole standard.
  await expect(page.getByTestId('compliance-matrix-coverage')).toContainText('requirements in this pack')
  await expect(page.getByTestId('compliance-matrix-counts')).toContainText('Satisfied')
  await expect(page.getByTestId('compliance-matrix-counts')).toContainText('Not covered')

  // Hiding not covered rows leaves only rows with a countermeasure.
  const rows = matrix.locator('[data-matrix-requirement]')
  const allRows = await rows.count()
  await page.getByLabel('Show not covered').click()
  expect(await rows.count()).toBeLessThanOrEqual(allRows)
  await expect(matrix.locator('[data-matrix-requirement]', { hasText: 'Not covered' })).toHaveCount(0)

  // A countermeasure number opens it in Threat Analysis.
  const link = matrix.getByRole('link').first()
  const number = (await link.textContent())?.trim() ?? ''
  await link.click()
  await expect(page).toHaveURL(new RegExp(`/threat-analysis/components\\?countermeasure=${number}$`))
  await expect(page.getByTestId('countermeasure-detail-dialog')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByTestId('countermeasure-detail-dialog')).toContainText(number)
})
