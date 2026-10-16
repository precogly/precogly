import { expect, test, type Page } from '@playwright/test'

/**
 * The "By Use Case" view of threat analysis: four numbered columns that
 * follow the chain use case, abuse case, threat, countermeasure.
 *
 * Runs against the seeded compose stack (e2e/global-setup.ts) on "Sample AWS
 * Serverless Web App". Names carry a timestamp, so reruns do not collide.
 */

const SAMPLE_MODEL = 'Sample AWS Serverless Web App'

async function openUseCaseView(page: Page) {
  await page.goto('/threat-models')
  await page.getByText(SAMPLE_MODEL).first().click()
  await page.getByRole('tab', { name: /Threat Analysis/ }).click()
  await expect(page.getByTestId('analysis-tree')).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'By Use Case' }).click()
  await expect(page.getByTestId('use-case-column')).toBeVisible()
}

test('the chain runs left to right: use case, abuse case, threat, countermeasures', async ({ page }) => {
  await openUseCaseView(page)
  const stamp = Date.now()
  const useCaseName = `Place order ${stamp}`
  const abuseCaseName = `Card testing ${stamp}`
  const threatName = `Scripted checkout with stolen cards ${stamp}`

  // The four columns carry their step numbers.
  for (const [step, title] of [
    ['1', 'Use cases'],
    ['2', 'Abuse cases'],
    ['3', 'Threats'],
    ['4', 'Countermeasures'],
  ]) {
    await expect(page.getByLabel(`Step ${step}`).locator('..')).toContainText(title)
  }

  // Step 1: add a use case; it is selected and column 2 asks for its abuse cases.
  await page.getByTestId('use-case-view-step-1').getByRole('button', { name: 'Add', exact: true }).click()
  const useCaseDialog = page.getByRole('dialog', { name: 'Add use case' })
  await useCaseDialog.getByLabel('Name').fill(useCaseName)
  await useCaseDialog.getByRole('button', { name: 'Add use case' }).click()
  await expect(useCaseDialog).toBeHidden()
  const useCaseRow = page.locator('[data-tree-key^="use-case-"]', { hasText: useCaseName })
  await expect(useCaseRow).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByTestId('abuse-case-column-label')).toHaveText(`How ${useCaseName} can be misused`)
  await expect(page.getByTestId('selection-label')).toHaveText('Select an abuse case')

  // Step 2: add an abuse case under it; it is linked to the use case and selected.
  await page.getByTestId('use-case-view-step-2').getByRole('button', { name: 'Add', exact: true }).click()
  const abuseCaseDialog = page.getByRole('dialog', { name: 'Add abuse case' })
  await abuseCaseDialog.getByLabel('Name').fill(abuseCaseName)
  await abuseCaseDialog.getByRole('button', { name: 'Add abuse case' }).click()
  await expect(abuseCaseDialog).toBeHidden()
  const abuseCaseRow = page.getByTestId('abuse-case-column').locator('[data-tree-key^="abuse-case-"]', { hasText: abuseCaseName })
  await expect(abuseCaseRow).toHaveAttribute('aria-pressed', 'true')
  await expect(abuseCaseRow.getByText('No threat')).toBeVisible()
  await expect(useCaseRow).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByTestId('selection-label')).toHaveText(`${abuseCaseName} (abuse case)`)

  // Step 3: add a threat to the abuse case.
  await page.getByTestId('use-case-view-step-3').getByRole('button', { name: 'Add', exact: true }).click()
  await page.getByRole('tab', { name: 'Custom threat' }).click()
  await page.getByLabel('Threat name *').fill(threatName)
  const wholeSystem = page.getByLabel('Applies to the whole system (no targets)')
  if (!(await wholeSystem.isChecked())) await wholeSystem.check()
  await page.getByRole('button', { name: 'Add custom threat' }).click()
  const threatRow = page.locator('[data-threat-number]', { hasText: threatName })
  await expect(threatRow).toBeVisible()
  await expect(abuseCaseRow.getByText('No threat')).toHaveCount(0)

  // Step 4: selecting the threat fills the countermeasures column.
  const threatNumber = (await threatRow.getAttribute('data-threat-number')) ?? ''
  await page.getByRole('button', { name: new RegExp(`^Open ${threatNumber} `) }).click()
  const threatModal = page.getByTestId('threat-detail-dialog')
  await expect(threatModal).toBeVisible()
  await expect(threatModal.getByTestId('from-abuse-cases')).toContainText(abuseCaseName)
  await page.keyboard.press('Escape')
  await expect(threatModal).toBeHidden()
  await expect(page.getByText('Select a threat')).toHaveCount(0)
  await expect(page.getByText('No countermeasures linked to this threat.')).toBeVisible()

  // Going back to step 1 clears the later steps.
  await useCaseRow.click()
  await expect(page.getByTestId('selection-label')).toHaveText('Select an abuse case')
  await expect(page.locator('[data-threat-number]', { hasText: threatName })).toHaveCount(0)
})
