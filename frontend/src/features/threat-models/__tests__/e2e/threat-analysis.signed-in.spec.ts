import { expect, test, type Page } from '@playwright/test'

/**
 * Threat analysis screen (plan 11.3, step 15 e2e; UX simplification phases 3
 * and 4): a multi-target threat, a whole-system threat, a zone target,
 * numbers, the table search, the three-thing rows, the threat and
 * countermeasure modals with their URL parameters, and the start selection.
 *
 * Runs against the seeded compose stack (e2e/global-setup.ts) on the sample
 * model "Sample AWS Serverless Web App".
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

/**
 * Selects a component row with threats of its own. A parent row can show an
 * "exposed" count for its subtree while holding none itself, so try each.
 */
async function selectComponentWithThreats(page: Page): Promise<void> {
  const candidates = page.locator('[data-tree-key^="component-"]').filter({ hasText: /exposed/ })
  const candidateCount = await candidates.count()
  for (let index = 0; index < candidateCount; index += 1) {
    await candidates.nth(index).click()
    await expect(page.getByTestId('selection-label')).toContainText('(component)')
    if ((await page.locator('[data-threat-number]').count()) > 0) return
  }
  throw new Error('No component with threats of its own in the sample model')
}

/** Opens the threat modal of a row by its number. */
async function openThreatModal(page: Page, number: string) {
  await page.getByRole('button', { name: new RegExp(`^Open ${number} `) }).click()
  const dialog = page.getByTestId('threat-detail-dialog')
  await expect(dialog).toBeVisible()
  return dialog
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

    const row = page.locator('[data-threat-number]', { hasText: 'No incident response plan' }).last()
    await expect(row).toBeVisible()
    await expect(row.locator('[data-number]').first()).toHaveText(/^T\d+$/)

    // The row shows number, title and state; "whole system" is in the modal.
    const number = (await row.getAttribute('data-threat-number')) ?? ''
    const dialog = await openThreatModal(page, number)
    await expect(dialog.getByText('whole system', { exact: true })).toBeVisible()
    await expect(dialog.getByText('The whole system (no targets).')).toBeVisible()
  })

  test('a component threat gets a number, and a second target makes it shared', async ({ page }) => {
    await openThreatAnalysis(page)

    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    expect(number).toMatch(/^T\d+$/)

    // Edit targets from the threat modal: add a flow as a second target.
    const threatModal = await openThreatModal(page, number)
    await threatModal.getByRole('button', { name: 'Edit targets' }).click()
    const dialog = page.getByRole('dialog', { name: `${number} Edit targets` })
    await dialog.getByRole('combobox').click()
    // A flow not yet picked (an earlier run may have added one): its check box is unfilled.
    await page
      .getByRole('option', { name: /\(flow\)/ })
      .filter({ has: page.locator('.opacity-50') })
      .first()
      .click()
    await page.keyboard.press('Escape')
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(dialog).toBeHidden()

    await expect(threatModal.getByText('shared', { exact: true })).toBeVisible()

    // The flow target is a link: the modal closes and the tree selects the flow, which lists the same number.
    await threatModal.getByTestId('threat-targets').getByRole('button', { name: /\(flow\)$/ }).first().click()
    await expect(threatModal).toBeHidden()
    await expect(page.getByTestId('selection-label')).toContainText('(flow)')
    await expect(page.locator(`[data-threat-number="${number}"]`)).toBeVisible()
  })

  test('removing the last target asks before making a threat whole-system', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    const threatModal = await openThreatModal(page, number)
    await threatModal.getByRole('button', { name: 'Edit targets' }).click()
    const dialog = page.getByRole('dialog', { name: `${number} Edit targets` })
    // Remove every chip, then Save.
    // The chips shift as each goes, so always remove the first one left.
    const removeChipButtons = dialog.getByRole('button', { name: /^Remove / })
    while ((await removeChipButtons.count()) > 0) await removeChipButtons.first().click()
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
    // `.last()`: earlier runs may have left the same name on this sample model.
    await expect(page.locator('[data-threat-number]', { hasText: 'Lateral movement inside the zone' }).last()).toBeVisible()
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

  test('the screen never opens on two empty panes', async ({ page }) => {
    await openThreatAnalysis(page)
    await expect(page.getByTestId('selection-label')).not.toHaveText(/^Select the system/)
    await expect(page.locator('[data-threat-number]').first()).toBeVisible()
  })

  test('a threat row is number, title and state, and opens a modal kept in the URL', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    const row = page.locator(`[data-threat-number="${number}"]`)

    // Three things on the row: no triage select, no severity, no category chips.
    await expect(row.locator('[data-threat-status]')).toHaveCount(1)
    await expect(row.getByRole('combobox')).toHaveCount(0)

    const dialog = await openThreatModal(page, number)
    await expect(page).toHaveURL(new RegExp(`[?&]threat=${number}$`))
    await expect(row).toHaveAttribute('data-selected', 'true')
    for (const section of ['State', 'Description', 'Severity', 'Threat actor', 'Decision rationale', 'Threat sources', 'Attacker impact', 'Targets']) {
      await expect(dialog.getByText(section, { exact: true }).first()).toBeVisible()
    }
    await expect(dialog.getByRole('button', { name: 'Delete threat' })).toBeVisible()

    // Escape closes it and drops the parameter; the countermeasures stay on this threat.
    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
    await expect(page).not.toHaveURL(/[?&]threat=/)
    await expect(page.locator('[data-countermeasure-number]').first()).toBeVisible()

    // Reload with the parameter: the modal opens again on the same threat.
    await page.goto(`${new URL(page.url()).pathname}?threat=${number}`)
    await expect(page.getByTestId('threat-detail-dialog')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByTestId('threat-detail-dialog')).toContainText(number)
    await page.getByTestId('threat-detail-dialog').getByRole('button', { name: 'Close', exact: true }).last().click()
    await expect(page.getByTestId('threat-detail-dialog')).toBeHidden()
  })

  test('triage moves to the modal, with the rationale prompt', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    const dialog = await openThreatModal(page, number)

    await dialog.getByRole('combobox', { name: 'Triage' }).click()
    await page.getByRole('option', { name: 'Accept' }).click()
    await dialog.getByPlaceholder('Why is this the right decision?').fill('Covered by the network segmentation')
    await dialog.getByRole('button', { name: 'Confirm' }).click()
    await expect(dialog.getByTestId('threat-decision-rationale')).toHaveText('Covered by the network segmentation')

    // Back to Open, so the sample model keeps its state.
    await dialog.getByRole('combobox', { name: 'Triage' }).click()
    await page.getByRole('option', { name: 'Open' }).click()
    await page.keyboard.press('Escape')
    await expect(page.locator(`[data-threat-number="${number}"]`).first().locator('[data-threat-status]')).toBeVisible()
  })

  test('a countermeasure row is dot with word, number and name, and opens a modal', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    await openThreatModal(page, number)
    await page.keyboard.press('Escape')

    const countermeasureRow = page.locator('[data-countermeasure-number]').first()
    await expect(countermeasureRow).toBeVisible()
    const statusWord = countermeasureRow.locator('[data-countermeasure-status]')
    await expect(statusWord).toHaveText(/^(Gap|Planned|Verified|Platform|Waived|In Progress|Implemented)$/)
    await expect(countermeasureRow.getByText('Linked threats:')).toHaveCount(0)

    const countermeasureNumber = (await countermeasureRow.getAttribute('data-countermeasure-number')) ?? ''
    await countermeasureRow.getByRole('button', { name: /^Open / }).click()
    const dialog = page.getByTestId('countermeasure-detail-dialog')
    await expect(dialog).toBeVisible()
    await expect(page).toHaveURL(new RegExp(`[?&]countermeasure=${countermeasureNumber}$`))
    for (const section of ['Status', 'Tracking', 'Mitigates', 'Applies to']) {
      await expect(dialog.getByText(section, { exact: true }).first()).toBeVisible()
    }
    await expect(dialog.getByRole('button', { name: 'Advanced' })).toBeVisible()
    await dialog.getByRole('button', { name: 'Close', exact: true }).last().click()
    await expect(dialog).toBeHidden()
    await expect(page).not.toHaveURL(/[?&]countermeasure=/)
  })

  test('each view has its own URL, survives reload, and Back moves between views', async ({ page }) => {
    await openThreatAnalysis(page)
    await expect(page).toHaveURL(/\/threat-analysis\/components$/)

    await page.getByRole('button', { name: 'By Use Case' }).click()
    await expect(page).toHaveURL(/\/threat-analysis\/use-cases$/)
    await expect(page.getByTestId('use-case-column')).toBeVisible()
    await page.getByRole('button', { name: 'Table View' }).click()
    await expect(page).toHaveURL(/\/threat-analysis\/table$/)

    await page.reload()
    await expect(page.getByLabel('Search threats')).toBeVisible({ timeout: 15_000 })

    await page.goBack()
    await expect(page).toHaveURL(/\/threat-analysis\/use-cases$/)
    await expect(page.getByTestId('use-case-column')).toBeVisible({ timeout: 15_000 })

    // Leaving the tab and coming back returns to the last view.
    await page.getByRole('tab', { name: 'Overview' }).click()
    await expect(page.getByTestId('overview-diagrams-section')).toBeVisible()
    await page.getByRole('tab', { name: /Threat Analysis/ }).click()
    await expect(page).toHaveURL(/\/threat-analysis\/use-cases$/)

    // An unknown view goes to the components view.
    await page.goto(page.url().replace(/use-cases$/, 'no-such-view'))
    await expect(page).toHaveURL(/\/threat-analysis\/components$/)

    // The table's open icon lands on the components view with the threat's modal.
    await page.getByRole('button', { name: 'Table View' }).click()
    await page.locator('tbody [data-threat-number]').first().waitFor()
    const number = (await page.locator('tbody [data-threat-number]').first().getAttribute('data-threat-number')) ?? ''
    await page.getByRole('button', { name: `Open ${number}`, exact: true }).click()
    await expect(page).toHaveURL(new RegExp(`/threat-analysis/components\\?threat=${number}$`))
    await expect(page.getByTestId('threat-detail-dialog')).toBeVisible()
  })

  test('picking a common threat actor adds it to the model and to the abuse case picker', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    const number = await firstThreatNumber(page)
    const dialog = await openThreatModal(page, number)

    await dialog.getByRole('combobox', { name: 'Threat actor' }).click()
    // Wherever it is listed (common, or the model's own after an earlier run), picking it selects a record.
    await page.getByRole('option', { name: 'Insider Threat', exact: true }).click()
    await expect(dialog.getByRole('combobox', { name: 'Threat actor' })).toHaveText('Insider Threat')

    await dialog.getByRole('combobox', { name: 'Threat actor' }).click()
    const modelGroup = page.getByRole('group', { name: "This model's threat actors" })
    await expect(modelGroup.getByRole('option', { name: 'Insider Threat', exact: true })).toBeVisible()
    await expect(page.getByRole('group', { name: 'Common threat actors' }).getByRole('option', { name: 'Insider Threat' })).toHaveCount(0)
    await page.keyboard.press('Escape')

    await dialog.getByRole('button', { name: 'Manage threat actors' }).click()
    const manage = page.getByRole('dialog', { name: 'Threat actors' })
    await expect(manage.getByText('Insider Threat', { exact: true })).toBeVisible()
    await manage.getByRole('button', { name: 'Close' }).first().click()

    // The abuse case's picker offers the same list, without free text.
    await dialog.getByRole('button', { name: 'Close', exact: true }).last().click()
    await expect(dialog).toBeHidden()
    await page.getByRole('button', { name: 'By Use Case' }).click()
    await page.getByTestId('use-case-view-step-1').getByRole('button', { name: 'Add', exact: true }).click()
    const useCaseDialog = page.getByRole('dialog', { name: 'Add use case' })
    await useCaseDialog.getByLabel('Name').fill(`Actor check ${Date.now()}`)
    await useCaseDialog.getByRole('button', { name: 'Add use case' }).click()
    await page.getByTestId('use-case-view-step-2').getByRole('button', { name: 'Add', exact: true }).click()
    const abuseCaseDialog = page.getByRole('dialog', { name: 'Add abuse case' })
    await abuseCaseDialog.getByRole('combobox', { name: 'Threat actor' }).click()
    await expect(
      page.getByRole('group', { name: "This model's threat actors" }).getByRole('option', { name: 'Insider Threat', exact: true })
    ).toBeVisible()
    await expect(page.getByRole('option', { name: 'Custom text' })).toHaveCount(0)
    await page.keyboard.press('Escape')
  })

  test('a past due date makes a countermeasure overdue, and the chip filters the column to it', async ({ page }) => {
    await openThreatAnalysis(page)
    await selectComponentWithThreats(page)
    await openThreatModal(page, await firstThreatNumber(page))
    await page.keyboard.press('Escape')

    // A control not in effect, so a past date makes it overdue.
    const openRow = page
      .locator('[data-countermeasure-number]')
      .filter({ has: page.locator('[data-countermeasure-status="gap"], [data-countermeasure-status="planned"]') })
      .first()
    const countermeasureNumber = (await openRow.getAttribute('data-countermeasure-number')) ?? ''
    const openCountermeasure = async () => {
      await page.locator(`[data-countermeasure-number="${countermeasureNumber}"]`).first().getByRole('button', { name: /^Open / }).click()
      const dialog = page.getByTestId('countermeasure-detail-dialog')
      await expect(dialog).toBeVisible()
      return dialog
    }

    let dialog = await openCountermeasure()
    await dialog.getByLabel('Due date').fill('2020-01-01')
    await dialog.getByRole('button', { name: 'Close', exact: true }).last().click()

    const chip = page.getByTestId('overdue-filter')
    await expect(chip).toBeVisible()
    const overdueCount = Number((await chip.textContent())?.match(/\d+/)?.[0])
    await chip.click()
    await expect(chip).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator('[data-countermeasure-number]')).toHaveCount(overdueCount)
    await expect(page.locator(`[data-countermeasure-number="${countermeasureNumber}"]`)).toBeVisible()
    await chip.click()
    await expect(chip).toHaveAttribute('aria-pressed', 'false')

    // The model-wide list in the toolbar has it too, and opens it in place.
    await page.getByTestId('model-overdue-button').click()
    const overdueDialog = page.getByTestId('model-overdue-dialog')
    const overdueRow = overdueDialog.locator(`[data-overdue-number="${countermeasureNumber}"]`)
    await expect(overdueRow).toBeVisible()
    await overdueRow.getByRole('button').click()
    await expect(overdueDialog).toBeHidden()
    await expect(page).toHaveURL(new RegExp(`/threat-analysis/components\\?countermeasure=${countermeasureNumber}$`))
    await expect(page.getByTestId('countermeasure-detail-dialog')).toBeVisible()
    await page.getByTestId('countermeasure-detail-dialog').getByRole('button', { name: 'Close', exact: true }).last().click()

    // Clean up: clear the date again.
    dialog = await openCountermeasure()
    await dialog.getByLabel('Due date').fill('')
    await dialog.getByRole('button', { name: 'Close', exact: true }).last().click()
    await expect(dialog).toBeHidden()
  })
})
