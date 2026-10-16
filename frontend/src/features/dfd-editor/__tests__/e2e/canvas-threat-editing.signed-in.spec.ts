import { expect, test, type Page } from '@playwright/test'

/**
 * Editing a threat from the diagram: the Threats section of a node's panel
 * lists the node's threats, and a card opens the same threat modal as the
 * threat analysis screen. Renaming shows on the card; triaging moves the
 * threat to the collapsed "triaged" line, from where it can be reopened. A
 * card's countermeasure status follows the workspace rules: Planned asks
 * for an owner, Waived for a reason.
 *
 * Runs against the seeded compose stack (e2e/global-setup.ts) on the sample
 * model "Sample LNG Process Control". The threats it adds stay on the model.
 */

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000'
const SAMPLE_MODEL_NAME = 'Sample LNG Process Control'
const NODE_LABEL = 'Compressor PLC'

interface ThreatModelRow {
  id: number | string
  name: string
}

interface DiagramRow {
  id: number | string
  isPrimary?: boolean
  is_primary?: boolean
}

/** Resolve the sample model and its primary diagram over the API with the stored token. */
async function openSampleDiagram(page: Page): Promise<void> {
  await page.goto('/threat-models')
  await expect(page).not.toHaveURL(/\/login/)
  const accessToken = await page.evaluate(() => localStorage.getItem('precogly_access_token'))
  if (!accessToken) throw new Error('no access token in the signed-in storage state')
  const headers = { Authorization: `Bearer ${accessToken}` }

  const modelsResponse = await page.request.get(`${API_URL}/api/threat-models/`, { headers })
  expect(modelsResponse.ok()).toBe(true)
  const modelsBody = (await modelsResponse.json()) as ThreatModelRow[] | { results: ThreatModelRow[] }
  const models = Array.isArray(modelsBody) ? modelsBody : modelsBody.results
  const sampleModel = models.find((model) => model.name === SAMPLE_MODEL_NAME)
  if (!sampleModel) throw new Error(`${SAMPLE_MODEL_NAME} is not seeded`)

  const diagramsResponse = await page.request.get(`${API_URL}/api/diagrams/?threat_model=${sampleModel.id}`, { headers })
  expect(diagramsResponse.ok()).toBe(true)
  const diagramsBody = (await diagramsResponse.json()) as DiagramRow[] | { results: DiagramRow[] }
  const diagrams = Array.isArray(diagramsBody) ? diagramsBody : diagramsBody.results
  const primary = diagrams.find((diagram) => diagram.isPrimary ?? diagram.is_primary) ?? diagrams[0]
  if (!primary) throw new Error(`${SAMPLE_MODEL_NAME} has no diagram`)

  await page.goto(`/threat-models/${sampleModel.id}/diagrams/${primary.id}`)
  await expect(page.locator('.react-flow__node').first()).toBeVisible({ timeout: 15_000 })
}

test('a threat card in the node panel opens the threat modal; a rename shows on the card and triage removes it', async ({ page }) => {
  await openSampleDiagram(page)

  await page.locator('.react-flow__node-process', { hasText: NODE_LABEL }).getByText(NODE_LABEL).click()

  // Add a custom threat on this node, so the test edits a row of its own.
  const threatName = `Firmware rollback ${Date.now()}`
  await page.getByRole('button', { name: 'Add Threat' }).click()
  await page.getByRole('tab', { name: 'Custom threat' }).click()
  await page.getByLabel('Threat name *').fill(threatName)
  await page.getByRole('button', { name: 'Add custom threat' }).click()

  const card = page.getByTestId('canvas-threat-card').filter({ hasText: threatName })
  await expect(card).toBeVisible()
  const number = (await card.getAttribute('data-threat-number')) ?? ''
  expect(number).toMatch(/^T\d+$/)

  // The card opens the same modal as the threat analysis screen.
  await card.click()
  const dialog = page.getByTestId('threat-detail-dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText(threatName)

  // Rename from the modal: the card shows the new name once the query refreshes.
  const renamed = `${threatName} (renamed)`
  await dialog.getByRole('button', { name: threatName }).click()
  await dialog.getByLabel('Threat name').fill(renamed)
  await dialog.getByLabel('Threat name').press('Enter')
  await expect(dialog).toContainText(renamed)
  await expect(page.locator(`[data-testid="canvas-threat-card"][data-threat-number="${number}"]`)).toContainText(renamed)

  // Accepting the threat needs a rationale; afterwards it leaves the cards for
  // the collapsed "triaged" line, and the modal stays open on it.
  await dialog.getByLabel('Triage').click()
  await page.getByRole('option', { name: 'Accept', exact: true }).click()
  await dialog.getByPlaceholder('Why is this the right decision?').fill('Rollback is blocked by signed firmware')
  await dialog.getByRole('button', { name: 'Confirm' }).click()
  await expect(dialog.getByLabel('Triage')).toContainText('Accept')
  await expect(page.locator(`[data-testid="canvas-threat-card"][data-threat-number="${number}"]`)).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()

  // The triaged line opens the same modal, where the threat can be reopened.
  const triagedToggle = page.getByTestId('canvas-triaged-toggle')
  await expect(triagedToggle).toContainText(/^\d+ triaged$/)
  await triagedToggle.click()
  const triagedRow = page.locator(`[data-testid="canvas-triaged-threat"][data-threat-number="${number}"]`)
  await expect(triagedRow).toContainText('Accept')
  await triagedRow.click()
  await expect(dialog).toBeVisible()
  await dialog.getByLabel('Triage').click()
  await page.getByRole('option', { name: 'Open', exact: true }).click()
  await expect(page.locator(`[data-testid="canvas-threat-card"][data-threat-number="${number}"]`)).toBeVisible()
  await expect(triagedRow).toHaveCount(0)
})

test('a countermeasure status change on a card asks for an owner before Planned and a reason before Waived', async ({ page }) => {
  await openSampleDiagram(page)
  await page.locator('.react-flow__node-process', { hasText: NODE_LABEL }).getByText(NODE_LABEL).click()

  // A threat and a custom countermeasure of this test's own, so the owner starts empty.
  const threatName = `Unsigned config upload ${Date.now()}`
  await page.getByRole('button', { name: 'Add Threat' }).click()
  await page.getByRole('tab', { name: 'Custom threat' }).click()
  await page.getByLabel('Threat name *').fill(threatName)
  await page.getByRole('button', { name: 'Add custom threat' }).click()
  const card = page.getByTestId('canvas-threat-card').filter({ hasText: threatName })
  await expect(card).toBeVisible()

  const countermeasureName = `Config signing ${Date.now()}`
  await card.getByRole('button', { name: 'Add' }).click()
  await page.getByRole('tab', { name: 'Custom' }).click()
  await page.getByLabel('Countermeasure Name *').fill(countermeasureName)
  await page.getByRole('button', { name: 'Add Custom Countermeasure' }).click()
  const statusSelect = card.getByLabel(`Status of ${countermeasureName}`)
  await expect(statusSelect).toContainText('Gap')

  // Planned with no owner: the owner prompt, not a saved status. Cancel keeps Gap.
  await statusSelect.click()
  await page.getByRole('option', { name: 'Planned' }).click()
  const prompt = page.getByTestId('canvas-status-prompt')
  await expect(prompt).toContainText('A planned countermeasure needs an owner')
  await expect(page.getByTestId('threat-detail-dialog')).toHaveCount(0)
  await prompt.getByRole('button', { name: 'Cancel' }).click()
  await expect(prompt).toBeHidden()
  await expect(statusSelect).toContainText('Gap')

  // Waived: the reason prompt; the reason is required, then the status is saved.
  await statusSelect.click()
  await page.getByRole('option', { name: 'Waived' }).click()
  await expect(prompt).toContainText('Provide a reason for waiving')
  await expect(prompt.getByRole('button', { name: 'Waive with Reason' })).toBeDisabled()
  await prompt.getByPlaceholder(/Risk accepted/).fill('Covered by the signed firmware check')
  await prompt.getByRole('button', { name: 'Waive with Reason' }).click()
  await expect(prompt).toBeHidden()
  await expect(statusSelect).toContainText('Waived')
})

test('the countermeasure controls on a card do not open the threat modal', async ({ page }) => {
  await openSampleDiagram(page)

  await page.locator('.react-flow__node-process', { hasText: NODE_LABEL }).getByText(NODE_LABEL).click()
  const card = page.getByTestId('canvas-threat-card').first()
  await expect(card).toBeVisible()

  // "Add" opens the countermeasure dialog, not the threat modal.
  await card.getByRole('button', { name: 'Add' }).click()
  await expect(page.getByTestId('threat-detail-dialog')).toHaveCount(0)
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
})
