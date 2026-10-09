import { expect, test, type Page } from '@playwright/test'

/**
 * Threat analysis screen (plan 11.3, step 15 e2e): a multi-target threat, a
 * whole-system threat, a zone target, numbers, and the table search.
 *
 * Runs against the seeded compose stack (e2e/global-setup.ts) on the sample
 * model "Sample AWS Serverless Web App". NOT YET RUN: the dev database was
 * stale when this spec was written.
 */

const SAMPLE_MODEL = 'Sample AWS Serverless Web App'

async function openThreatAnalysis(page: Page) {
  await page.goto('/threat-models')
  await page.getByText(SAMPLE_MODEL).first().click()
  await page.getByRole('tab', { name: /Threat Analysis/ }).click()
  await expect(page.getByTestId('analysis-tree')).toBeVisible({ timeout: 15_000 })
}

/** The number badge of the first threat row in the Threats column. */
async function firstThreatNumber(page: Page): Promise<string> {
  const row = page.locator('[data-threat-number]').first()
  await expect(row).toBeVisible()
  return (await row.getAttribute('data-threat-number')) ?? ''
}

test.describe('threat analysis screen', () => {
  test('the tree has a System root, selecting it shows whole-system threats', async ({ page }) => {
    await openThreatAnalysis(page)

    const systemRow = page.locator('[data-tree-key="system"]')
    await expect(systemRow).toBeVisible()
    await systemRow.click()
    await expect(page.getByTestId('selection-label')).toHaveText('System')

    // Add a whole-system threat by hand.
    await page.getByRole('button', { name: 'Add', exact: true }).nth(1).click()
    await page.getByRole('tab', { name: 'Custom threat' }).click()
    await page.getByLabel('Threat name *').fill('No incident response plan')
    await expect(page.getByLabel('Applies to the whole system (no targets)')).toBeChecked()
    await page.getByRole('button', { name: 'Add custom threat' }).click()

    const row = page.locator('[data-threat-number]', { hasText: 'No incident response plan' })
    await expect(row).toBeVisible()
    await expect(row.getByText('whole system')).toBeVisible()
    await expect(row.locator('[data-number]').first()).toHaveText(/^T\d+$/)
  })

  test('a component threat gets a number, and a second target makes it shared', async ({ page }) => {
    await openThreatAnalysis(page)

    // The first component row of the tree.
    const componentRow = page.locator('[data-tree-key^="component-"]').first()
    await componentRow.click()
    const number = await firstThreatNumber(page)
    expect(number).toMatch(/^T\d+$/)

    // Edit targets: add a flow as a second target.
    const threatRow = page.locator(`[data-threat-number="${number}"]`)
    await threatRow.hover()
    await threatRow.getByRole('button', { name: `Edit targets of ${number}` }).click()
    const dialog = page.getByRole('dialog', { name: `${number} Edit targets` })
    await dialog.getByRole('combobox').click()
    await page.getByRole('option', { name: /\(flow\)/ }).first().click()
    await page.keyboard.press('Escape')
    await dialog.getByRole('button', { name: 'Save' }).click()

    await expect(threatRow.getByText('shared')).toBeVisible()
    await expect(threatRow.getByText('Also on:')).toBeVisible()

    // The flow row of the tree now lists the same number.
    await threatRow.getByRole('button', { name: /\(flow\)$/ }).click()
    await expect(page.getByTestId('selection-label')).toContainText('(flow)')
    await expect(page.locator(`[data-threat-number="${number}"]`)).toBeVisible()
  })

  test('removing the last target asks before making a threat whole-system', async ({ page }) => {
    await openThreatAnalysis(page)
    await page.locator('[data-tree-key^="component-"]').first().click()
    const number = await firstThreatNumber(page)
    const threatRow = page.locator(`[data-threat-number="${number}"]`)
    await threatRow.hover()
    await threatRow.getByRole('button', { name: `Edit targets of ${number}` }).click()
    const dialog = page.getByRole('dialog', { name: `${number} Edit targets` })
    // Remove every chip, then Save.
    for (const chip of await dialog.getByRole('button', { name: /^Remove/ }).all()) await chip.click()
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText(`${number} would have no targets`)).toBeVisible()
    await page.getByRole('button', { name: 'Cancel' }).last().click()
  })

  test('a zone is selectable and holds its own threats', async ({ page }) => {
    await openThreatAnalysis(page)
    const zoneRow = page.locator('[data-tree-key^="zone-"]').first()
    await zoneRow.click()
    await expect(page.getByTestId('selection-label')).toContainText('(zone)')
    await expect(page.getByText('Controls scoped here')).toBeVisible()

    await page.getByRole('button', { name: 'Add', exact: true }).nth(1).click()
    await page.getByRole('tab', { name: 'Custom threat' }).click()
    await page.getByLabel('Threat name *').fill('Lateral movement inside the zone')
    await page.getByRole('button', { name: 'Add custom threat' }).click()
    await expect(page.locator('[data-threat-number]', { hasText: 'Lateral movement inside the zone' })).toBeVisible()
  })

  test('the table view sorts by number and finds T7 by search', async ({ page }) => {
    await openThreatAnalysis(page)
    await page.getByRole('button', { name: 'Table View' }).click()

    const numbers = await page.locator('tbody [data-threat-number]').evaluateAll((rows) =>
      rows.map((row) => Number((row.getAttribute('data-threat-number') ?? 'T0').slice(1)))
    )
    expect(numbers).toEqual([...numbers].sort((left, right) => left - right))

    await page.getByLabel('Search threats').fill('T7')
    await expect(page.locator('tbody [data-threat-number]')).toHaveCount(1)
    await expect(page.locator('tbody [data-threat-number="T7"]')).toBeVisible()

    await page.getByLabel('Search threats').fill('zzz-no-such-threat')
    await expect(page.getByText('No threat matches the search.')).toBeVisible()
  })
})
