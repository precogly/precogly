import { expect, test, type Page } from '@playwright/test'

/**
 * The Review card, the blueprint switcher, the Overview's sections and the
 * tab URLs on the model page (plan 11.5, J2, L5, UX simplification phases 1
 * and 2) against the seeded "Sample AWS Serverless Web App".
 *
 * The seeded admin account is a Security Team member (seed.py gives it
 * OrganizationMember.Role.SECURITY_TEAM), so it may approve and revoke.
 *
 * Not yet run: the development database was stale when this spec was
 * written. Run it with the signed-in project once the compose stack is
 * reseeded (`docker compose down -v && docker compose up -d`).
 */

const SAMPLE_MODEL_NAME = 'Sample AWS Serverless Web App'

async function openSampleModel(page: Page): Promise<void> {
  await page.goto('/threat-models')
  await expect(page).not.toHaveURL(/\/login/)
  await page.getByText(SAMPLE_MODEL_NAME).first().click()
  await expect(page.getByTestId('review-card')).toBeVisible({ timeout: 15_000 })
}

/** Opens one of the Overview's three buttons (System, Business objectives, Use cases). */
async function openOverviewButton(page: Page, label: string): Promise<void> {
  await page.getByTestId('overview-detail-buttons').getByRole('button', { name: new RegExp(`^${label}`) }).click()
}

async function addObjective(page: Page, name: string): Promise<void> {
  await openOverviewButton(page, 'Business objectives')
  const objectives = page.getByRole('dialog', { name: 'Business objectives' })
  await objectives.getByRole('button', { name: 'Add objective' }).click()
  const dialog = page.getByRole('dialog', { name: 'Add objective' })
  await dialog.getByLabel('Objective').fill(name)
  await dialog.getByRole('button', { name: 'Add objective' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByTestId('business-objective-row').filter({ hasText: name })).toBeVisible()
  await objectives.getByRole('button', { name: 'Close' }).click()
  await expect(objectives).toBeHidden()
}

async function deleteObjective(page: Page, name: string): Promise<void> {
  await openOverviewButton(page, 'Business objectives')
  const objectives = page.getByRole('dialog', { name: 'Business objectives' })
  const row = page.getByTestId('business-objective-row').filter({ hasText: name })
  await row.getByRole('button', { name: `Delete ${name}` }).click()
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(row).toHaveCount(0)
  await objectives.getByRole('button', { name: 'Close' }).click()
  await expect(objectives).toBeHidden()
}

test('approving, editing and undoing moves the badge through the three states', async ({ page }) => {
  await openSampleModel(page)
  const badge = page.getByTestId('approval-state')

  // Start from a clean slate in case an earlier run left an approval behind.
  // The badge reads "Not approved" while the review state loads, so wait for it.
  await expect(page.getByTestId('review-card')).not.toContainText('Loading review state')
  await expect(page.getByRole('button', { name: 'Mark reviewed' })).toBeVisible()
  if ((await badge.textContent())?.trim() !== 'Not approved') {
    await page.getByRole('button', { name: 'Revoke' }).click()
    await expect(badge).toHaveText('Not approved')
  }

  await page.getByRole('button', { name: 'Mark reviewed' }).click()
  await expect(page.getByTestId('review-card')).toContainText('by admin@precogly.dev')

  await page.getByRole('button', { name: 'Approve', exact: true }).click()
  const signOff = page.getByTestId('approve-sign-off')
  await expect(signOff).toBeVisible()
  await expect(signOff).toContainText('Before you approve')
  await signOff.getByRole('button', { name: /Approve/ }).click()
  await expect(signOff).toBeHidden()
  await expect(badge).toHaveText('Approved')

  // Any change to the model's content counts: a business objective is one.
  const objectiveName = `Keep checkout up ${Date.now()}`
  await addObjective(page, objectiveName)
  await expect(badge).toHaveText('Changed since approval')

  // Undoing the change brings the approval back: the content digest matches again.
  await deleteObjective(page, objectiveName)
  await expect(badge).toHaveText('Approved')

  await page.getByRole('button', { name: 'Revoke' }).click()
  await expect(badge).toHaveText('Not approved')
})

test('a second blueprint shows the switcher, which drives the system context dialog', async ({ page }) => {
  await openSampleModel(page)

  // One blueprint: no switcher, the actions sit in the small menu.
  await expect(page.getByTestId('blueprint-switcher')).toHaveCount(0)
  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Add blueprint' }).click()

  const manage = page.getByTestId('manage-blueprints')
  await expect(manage).toBeVisible()
  const blueprintName = `Plant network view ${Date.now()}`
  await manage.getByLabel('Name').fill(blueprintName)
  await manage.getByRole('combobox').click()
  await page.getByRole('option', { name: 'Data flow' }).click()
  await page.keyboard.press('Escape')
  await manage.getByRole('button', { name: 'Add blueprint' }).click()
  await expect(manage.getByTestId('blueprint-row').filter({ hasText: blueprintName })).toBeVisible()
  await page.keyboard.press('Escape')

  // Two blueprints: the switcher appears, in the header and beside the
  // diagrams on the Overview, and selects the new one.
  await expect(page.getByTestId('blueprint-switcher')).toHaveCount(2)
  const switcher = page.getByTestId('blueprint-switcher').first()
  await expect(switcher).toBeVisible()
  await switcher.click()
  await page.getByRole('menuitemradio', { name: blueprintName }).click()
  await expect(switcher).toContainText(blueprintName)
  await expect(page).toHaveURL(/blueprint=\d+/)

  // The system context dialog's blueprint select is preset to the switcher's blueprint.
  await openOverviewButton(page, 'System')
  await page.getByRole('tab', { name: 'Context' }).click()
  await expect(page.getByTestId('context-blueprint-select')).toContainText(blueprintName)
  await page.keyboard.press('Escape')

  // Clean up: delete the blueprint through the manage dialog (the preview says it is empty).
  await switcher.click()
  await page.getByRole('menuitem', { name: 'Manage blueprints...' }).click()
  const row = manage.getByTestId('blueprint-row').filter({ hasText: blueprintName })
  await row.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('The blueprint is empty.')).toBeVisible()
  await page.getByRole('button', { name: 'Delete blueprint' }).click()
  await expect(row).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('blueprint-switcher')).toHaveCount(0)
})

test('each tab has its own URL, survives reload, and Back and Forward move between tabs', async ({ page }) => {
  await openSampleModel(page)
  await expect(page).toHaveURL(/\/threat-models\/\d+\/overview$/)
  const modelPath = new URL(page.url()).pathname.replace(/\/overview$/, '')

  await page.getByRole('tab', { name: /Threat Analysis/ }).click()
  await expect(page).toHaveURL(new RegExp(`${modelPath}/threat-analysis/components$`))
  await page.getByRole('tab', { name: 'Risk Analysis' }).click()
  await expect(page).toHaveURL(new RegExp(`${modelPath}/risk-analysis$`))

  await page.reload()
  await expect(page.getByRole('tab', { name: 'Risk Analysis' })).toHaveAttribute('data-state', 'active')

  await page.goBack()
  await expect(page).toHaveURL(new RegExp(`${modelPath}/threat-analysis/components$`))
  await expect(page.getByRole('tab', { name: /Threat Analysis/ })).toHaveAttribute('data-state', 'active')
  await page.goForward()
  await expect(page).toHaveURL(new RegExp(`${modelPath}/risk-analysis$`))

  // An unknown tab goes to the overview, and the query string survives a tab change.
  await page.goto(`${modelPath}/no-such-tab?blueprint=1`)
  await expect(page).toHaveURL(new RegExp(`${modelPath}/overview\\?blueprint=1$`))
  await page.getByRole('tab', { name: 'Pentests' }).click()
  await expect(page).toHaveURL(new RegExp(`${modelPath}/pentests\\?blueprint=1$`))
})

test('the overview lists diagrams, review, three buttons, connections and reference images', async ({ page }) => {
  await openSampleModel(page)

  // Top to bottom, in this order.
  const sectionTops = await Promise.all(
    [
      page.getByTestId('overview-diagrams-section'),
      page.getByTestId('review-card'),
      page.getByTestId('overview-detail-buttons'),
      page.getByTestId('overview-connections-section'),
      page.getByTestId('overview-reference-images-section'),
    ].map(async (locator) => (await locator.boundingBox())?.y ?? -1)
  )
  expect(sectionTops.every((top) => top >= 0)).toBe(true)
  expect(sectionTops).toEqual([...sectionTops].sort((left, right) => left - right))

  // "+ New DFD" is the one primary action; the counts strip is gone.
  await expect(page.getByRole('button', { name: 'New DFD' })).toBeVisible()
  await expect(page.getByText('In-Scope Components')).toHaveCount(0)

  // The four buttons open dialogs with the cards that used to sit on the page.
  // System Details and System context share one dialog with two tabs.
  await openOverviewButton(page, 'System')
  await expect(page.getByTestId('model-details-card')).toBeVisible()
  await expect(page.getByTestId('primary-system-select')).toBeVisible()
  await page.getByTestId('model-details-card').getByRole('button', { name: 'Edit' }).click()
  await expect(page.getByRole('tab', { name: 'Context' })).toHaveAttribute('data-state', 'active')
  await expect(page.getByRole('button', { name: 'Submit' })).toBeVisible()
  await page.keyboard.press('Escape')
  await openOverviewButton(page, 'Use cases')
  await expect(page.getByTestId('use-cases-card')).toBeVisible()
  await page.keyboard.press('Escape')

  // Connections is collapsed; open, it shows four cards, Blueprints among them.
  const connections = page.getByTestId('overview-connections-section')
  await expect(page.getByTestId('blueprints-card')).toBeHidden()
  await connections.getByRole('button', { name: /Connections/ }).click()
  await expect(page.getByTestId('blueprints-card')).toContainText('formerly Connected Systems')
  await page.getByTestId('blueprints-card').click()
  await expect(page.getByTestId('manage-blueprints')).toBeVisible()
  await page.keyboard.press('Escape')
})
