import { expect, test, type Page } from '@playwright/test'

/**
 * Zone, flow and boundary types in the DFD editor (plan 11.2), driven
 * against the seeded "Sample LNG Process Control" model, whose primary
 * diagram comes from the ot-ics/lng-process-control template: network zones
 * with trust levels, signal and control flows, and one network boundary
 * ("IDMZ conduit").
 *
 * NOT YET RUN: the dev database was stale when this was written. It needs
 * the seeded compose stack (`docker compose up -d`) and the signed-in
 * project of playwright.config.ts.
 */

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000'
const SAMPLE_MODEL_NAME = 'Sample LNG Process Control'

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

  const diagramsResponse = await page.request.get(
    `${API_URL}/api/diagrams/?threat_model=${sampleModel.id}`,
    { headers },
  )
  expect(diagramsResponse.ok()).toBe(true)
  const diagramsBody = (await diagramsResponse.json()) as DiagramRow[] | { results: DiagramRow[] }
  const diagrams = Array.isArray(diagramsBody) ? diagramsBody : diagramsBody.results
  const primary = diagrams.find((diagram) => diagram.isPrimary ?? diagram.is_primary) ?? diagrams[0]
  if (!primary) throw new Error(`${SAMPLE_MODEL_NAME} has no diagram`)

  await page.goto(`/threat-models/${sampleModel.id}/diagrams/${primary.id}`)
  await expect(page.locator('.react-flow__node').first()).toBeVisible({ timeout: 15_000 })
}

/** Click an edge through its wrapper; the label sits in a portal and the path is thin. */
async function selectEdge(page: Page, edgeId: string): Promise<void> {
  const edge = page.locator(`.react-flow__edge[data-id="${edgeId}"]`)
  await expect(edge).toBeAttached()
  await edge.dispatchEvent('click')
}

test('a zone node carries its type and trust level, and the panel edits them', async ({ page }) => {
  await openSampleDiagram(page)

  // The canvas badge and the trust level indicator of a seeded network zone.
  const controlZone = page.locator('.react-flow__node-trustZone', {
    hasText: 'Control Network (Level 0-1)',
  })
  await expect(controlZone.getByTestId('zone-type-badge')).toHaveText('Network zone')
  await expect(controlZone.getByTestId('zone-trust-level')).toHaveText('TL: 90')

  await controlZone.getByText('Control Network (Level 0-1)').click()

  // The panel: "Zone" with the type badge, the type select and the level.
  await expect(page.getByTestId('zone-type-select')).toContainText('Network zone')
  await expect(page.getByTestId('zone-trust-level-value')).toHaveText('90')

  // Clearing the level removes the canvas indicator: null means not set.
  await page.getByRole('button', { name: 'Clear' }).click()
  await expect(page.getByTestId('zone-trust-level-field')).toContainText('Not set')
  await expect(controlZone.getByTestId('zone-trust-level')).toHaveCount(0)

  // Setting it again starts at 50.
  await page.getByRole('button', { name: 'Set level' }).click()
  await expect(page.getByTestId('zone-trust-level-value')).toHaveText('50')
  await expect(controlZone.getByTestId('zone-trust-level')).toHaveText('TL: 50')

  // A zone type without a trust level hides the slider and the indicator.
  await page.getByTestId('zone-type-select').click()
  await page.getByRole('option', { name: 'Physical zone' }).click()
  await expect(controlZone.getByTestId('zone-type-badge')).toHaveText('Physical zone')
  await expect(page.getByTestId('zone-trust-level-field')).toHaveCount(0)
  await expect(controlZone.getByTestId('zone-trust-level')).toHaveCount(0)
})

test('a signal flow shows its type on the canvas and hides the data-only fields', async ({ page }) => {
  await openSampleDiagram(page)

  // "Control signals (4-20mA)" is a signal flow in the template.
  await selectEdge(page, 'edge-plc-actuators')
  const panel = page.getByTestId('flow-panel')
  await expect(panel).toBeVisible()
  await expect(panel.getByTestId('flow-type-select')).toContainText('Signal flow')
  await expect(panel.getByTestId('flow-protocol-select')).toHaveCount(0)
  await expect(panel.getByLabel('Encryption in Transit')).toHaveCount(0)
  await expect(panel.getByTestId('advanced-section')).toHaveCount(0)
  // Data assets stay available on every type.
  await expect(panel.getByTestId('flow-data-assets')).toBeVisible()

  const signalEdge = page.locator('.react-flow__edge[data-id="edge-plc-actuators"]')
  await expect(signalEdge.getByTestId('flow-type-chip')).toHaveText('Signal')

  // Switching to a data flow brings protocol, encryption and the port back.
  await panel.getByTestId('flow-type-select').click()
  await page.getByRole('option', { name: 'Data flow' }).click()
  await expect(panel.getByTestId('flow-protocol-select')).toBeVisible()
  await expect(panel.getByLabel('Encryption in Transit')).toBeVisible()
  await panel.getByRole('button', { name: 'Advanced' }).click()
  await expect(panel.getByLabel('Port')).toBeVisible()
  await expect(signalEdge.getByTestId('flow-type-chip')).toHaveCount(0)
})

test('the flow type filter hides signal flows without deleting them', async ({ page }) => {
  await openSampleDiagram(page)

  const signalEdge = page.locator('.react-flow__edge[data-id="edge-plc-actuators"]')
  await expect(signalEdge.locator('path').first()).toBeAttached()

  await page.getByTestId('flow-type-filter').click()
  await page.getByRole('menuitemcheckbox', { name: 'Signal flow' }).click()
  await page.keyboard.press('Escape')

  await expect(page.getByTestId('flow-type-filter')).not.toContainText('All flows')
  await expect(signalEdge.locator('path')).toHaveCount(0)
  // A data flow is still drawn.
  await expect(page.locator('.react-flow__edge[data-id="edge-firewall-scada"] path').first()).toBeAttached()

  await page.getByTestId('flow-type-filter').click()
  await page.getByRole('menuitem', { name: 'Show all flows' }).click()
  await expect(signalEdge.locator('path').first()).toBeAttached()
})

test('the boundary panel shows the type, the pickers and the advanced crossing fields', async ({ page }) => {
  await openSampleDiagram(page)

  // "IDMZ conduit" is a network boundary with certificate authentication,
  // an ACL, and validation, logging and monitoring switched on.
  const boundaryEdge = page.locator('.react-flow__edge[data-id="boundary-ot-idmz"]')
  await expect(boundaryEdge.getByTestId('boundary-type-label')).toHaveText('Network boundary')

  await selectEdge(page, 'boundary-ot-idmz')
  const panel = page.getByTestId('boundary-panel')
  await expect(panel).toBeVisible()
  await expect(panel.getByTestId('boundary-type-select')).toContainText('Network boundary')
  await expect(panel.getByText('Certificate', { exact: true })).toBeVisible()
  await expect(panel.getByLabel('ACL')).toBeChecked()

  await panel.getByRole('button', { name: 'Advanced' }).click()
  await expect(panel.getByLabel('Data is validated when crossing')).toBeChecked()
  await expect(panel.getByLabel('Crossings are logged')).toBeChecked()
  await expect(panel.getByLabel('Crossings are monitored')).toBeChecked()
  await expect(panel.getByLabel('Rate limit')).toHaveValue('')

  // Token and logout settings are still there.
  await expect(panel.getByText('Token Configuration')).toBeVisible()
  await expect(panel.getByText('Logout Capabilities')).toBeVisible()
})
