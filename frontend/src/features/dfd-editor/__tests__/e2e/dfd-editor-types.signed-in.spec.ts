import fs from 'node:fs'
import path from 'node:path'

import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'

import { SIGNED_IN_STORAGE_STATE } from '../../../../../e2e/global-setup'

/**
 * Zone, flow and boundary types in the DFD editor (plan 11.2): network zones
 * with trust levels, signal and control flows, and one network boundary
 * ("IDMZ conduit").
 *
 * The spec builds its own threat model and diagram through the API, from the
 * canvas of the LNG process control template in fixtures/. The seed no longer
 * has an OT sample, and this spec tests the editor, not a pack. The fixture
 * carries no database ids and no component_ref, so it cannot bind to rows of
 * any other model. The model is removed afterwards.
 */

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8000'
const MODEL_NAME = 'E2E editor types (LNG canvas)'
const FIXTURE_CANVAS = JSON.parse(
  fs.readFileSync(
    path.join(process.cwd(), 'src/features/dfd-editor/__tests__/e2e/fixtures/lng-process-control-canvas.json'),
    'utf-8',
  ),
) as Record<string, unknown>

let api: APIRequestContext
let threatModelId: number | string
let diagramId: number | string

/** The access token global-setup stored for the signed-in project. */
function storedAccessToken(): string {
  const storageState = JSON.parse(fs.readFileSync(SIGNED_IN_STORAGE_STATE, 'utf-8')) as {
    origins: { localStorage: { name: string; value: string }[] }[]
  }
  const entry = storageState.origins
    .flatMap((origin) => origin.localStorage)
    .find((item) => item.name === 'precogly_access_token')
  if (!entry) throw new Error('no access token in the signed-in storage state')
  return entry.value
}

test.beforeAll(async () => {
  api = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${storedAccessToken()}` },
  })

  const modelResponse = await api.post('/api/threat-models/', { data: { name: MODEL_NAME } })
  expect(modelResponse.ok(), await modelResponse.text()).toBe(true)
  threatModelId = ((await modelResponse.json()) as { id: number | string }).id

  // The same two calls the app makes: create the diagram, then save its canvas,
  // which syncs the zones, flows and boundary to rows.
  const diagramResponse = await api.post('/api/diagrams/create_for_threat_model/', {
    data: { threatModelId, name: 'LNG process control', canvas_data: FIXTURE_CANVAS },
  })
  expect(diagramResponse.ok(), await diagramResponse.text()).toBe(true)
  diagramId = ((await diagramResponse.json()) as { id: number | string }).id

  const saveResponse = await api.patch(`/api/diagrams/${diagramId}/`, { data: { canvas_data: FIXTURE_CANVAS } })
  expect(saveResponse.ok(), await saveResponse.text()).toBe(true)
})

test.afterAll(async () => {
  if (threatModelId !== undefined) {
    await api.delete(`/api/threat-models/${threatModelId}/`)
  }
  await api?.dispose()
})

/** Open the diagram this spec created. */
async function openSampleDiagram(page: Page): Promise<void> {
  await page.goto(`/threat-models/${threatModelId}/diagrams/${diagramId}`)
  await expect(page).not.toHaveURL(/\/login/)
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

  // Edge labels are drawn in React Flow's label layer, outside the edge element; they carry the edge id.
  const signalEdgeLabel = page.locator('.react-flow__edgelabel-renderer [data-id="edge-plc-actuators"]')
  await expect(signalEdgeLabel.getByTestId('flow-type-chip')).toHaveText('Signal')

  // Switching to a data flow brings protocol, encryption and the port back.
  await panel.getByTestId('flow-type-select').click()
  await page.getByRole('option', { name: 'Data flow' }).click()
  await expect(panel.getByTestId('flow-protocol-select')).toBeVisible()
  await expect(panel.getByLabel('Encryption in Transit')).toBeVisible()
  await panel.getByRole('button', { name: 'Advanced' }).click()
  await expect(panel.getByLabel('Port')).toBeVisible()
  await expect(signalEdgeLabel.getByTestId('flow-type-chip')).toHaveCount(0)

  // Put the seeded flow back, so the next run (and autosave) finds it as a signal flow.
  await panel.getByTestId('flow-type-select').click()
  await page.getByRole('option', { name: 'Signal flow' }).click()
  await expect(signalEdgeLabel.getByTestId('flow-type-chip')).toHaveText('Signal')
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

  // Reopen only once the first menu has finished closing; a click while it closes is swallowed.
  await expect(page.getByRole('menu')).toHaveCount(0)
  await page.getByTestId('flow-type-filter').click()
  await expect(page.getByRole('menu')).toBeVisible()
  await page.getByRole('menuitem', { name: 'Show all flows' }).click()
  await expect(signalEdge.locator('path').first()).toBeAttached()
})

test('the boundary panel shows the type, the pickers and the advanced crossing fields', async ({ page }) => {
  await openSampleDiagram(page)

  // "IDMZ conduit" is a network boundary with certificate authentication,
  // an ACL, and validation, logging and monitoring switched on.
  const boundaryEdgeLabel = page.locator('.react-flow__edgelabel-renderer [data-id="boundary-ot-idmz"]')
  await expect(boundaryEdgeLabel.getByTestId('boundary-type-label')).toHaveText('Network boundary')

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
