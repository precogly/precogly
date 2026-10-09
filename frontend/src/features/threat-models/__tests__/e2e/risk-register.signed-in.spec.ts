import { expect, test, type Page } from '@playwright/test'

/**
 * The Risk Register tab (plan 11.4) against the seeded sample model.
 *
 * The seed fills "Sample AWS Serverless Web App" with risks across several
 * lifecycle statuses (backend/apps/core/management/commands/seed.py,
 * SAMPLE_RISKS and SAMPLE_RISK_RESPONSES), so the board has cards in at
 * least the identified, assessed, transferred and accepted columns.
 *
 * Not yet run: the development database was stale when this spec was
 * written. Run it with the signed-in project once the compose stack is
 * reseeded (`docker compose down -v && docker compose up -d`).
 */

const SAMPLE_MODEL_NAME = 'Sample AWS Serverless Web App'

async function openRiskTab(page: Page): Promise<void> {
  await page.goto('/threat-models')
  await expect(page).not.toHaveURL(/\/login/)
  await page.getByText(SAMPLE_MODEL_NAME).first().click()
  await page.getByRole('tab', { name: 'Risk Analysis' }).click()
  await expect(page.getByRole('heading', { name: 'Risk Register' })).toBeVisible({ timeout: 15_000 })
}

test('the board groups risks by lifecycle status', async ({ page }) => {
  await openRiskTab(page)

  await page.getByRole('button', { name: 'Board view' }).click()
  const board = page.getByTestId('risk-board')
  await expect(board).toBeVisible()

  for (const status of ['identified', 'assessed', 'mitigated', 'accepted', 'transferred', 'retired']) {
    await expect(board.getByTestId(`risk-column-${status}`)).toBeVisible()
  }

  // The seed sets a status per risk; the identified and assessed columns
  // both hold cards, and no card is in the retired column.
  await expect(board.getByTestId('risk-column-identified').getByTestId('risk-card').first()).toBeVisible()
  await expect(board.getByTestId('risk-column-assessed').getByTestId('risk-card').first()).toBeVisible()
  await expect(board.getByTestId('risk-column-retired').getByTestId('risk-card')).toHaveCount(0)
})

test('opening a risk shows its status, exposure, statement and ratings', async ({ page }) => {
  await openRiskTab(page)

  await page.getByTestId('risk-row').first().click()
  const detail = page.getByTestId('risk-detail')
  await expect(detail).toBeVisible()

  await expect(detail.getByRole('combobox', { name: 'Risk status' })).toBeVisible()
  await expect(detail.getByText('Exposure (from linked threats)')).toBeVisible()
  await expect(detail.getByText('Source, event and impact in one sentence.')).toBeVisible()
  await expect(detail.getByTestId('risk-ratings')).toContainText('Inherent:')
  await expect(detail.getByTestId('risk-ratings')).toContainText('Residual:')
  await expect(detail.getByTestId('risk-ratings')).toContainText('Target:')
})

test('a response can be added to a risk', async ({ page }) => {
  await openRiskTab(page)

  await page.getByTestId('risk-row').first().click()
  const detail = page.getByTestId('risk-detail')
  const responses = detail.getByTestId('risk-responses')
  const rowsBefore = await responses.getByTestId('risk-response-row').count()

  await responses.getByRole('button', { name: 'Add response' }).click()
  const dialog = page.getByRole('dialog', { name: 'Add response' })
  await expect(dialog).toBeVisible()

  await dialog.getByRole('combobox', { name: 'Strategy' }).click()
  await page.getByRole('option', { name: 'Transfer' }).click()
  const description = `Cyber insurance for downtime ${Date.now()}`
  await dialog.getByLabel('Description').fill(description)
  await dialog.getByLabel('Target date').fill('2027-01-01')
  await dialog.getByRole('button', { name: 'Add response' }).click()

  await expect(dialog).toBeHidden()
  await expect(responses.getByTestId('risk-response-row')).toHaveCount(rowsBefore + 1)
  const newRow = responses.getByTestId('risk-response-row').filter({ hasText: description })
  await expect(newRow).toContainText('Transfer')
  await expect(newRow).toContainText('Planned')
  await expect(newRow).toContainText('2027')
})
