import { expect, test, type Page } from '@playwright/test'

/**
 * The Review card and the blueprint switcher on the model page (plan 11.5,
 * J2, L5) against the seeded "Sample AWS Serverless Web App".
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

async function addObjective(page: Page, name: string): Promise<void> {
  await page.getByRole('button', { name: 'Add objective' }).click()
  const dialog = page.getByRole('dialog', { name: 'Add objective' })
  await dialog.getByLabel('Objective').fill(name)
  await dialog.getByRole('button', { name: 'Add objective' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByTestId('business-objective-row').filter({ hasText: name })).toBeVisible()
}

async function deleteObjective(page: Page, name: string): Promise<void> {
  const row = page.getByTestId('business-objective-row').filter({ hasText: name })
  await row.getByRole('button', { name: `Delete ${name}` }).click()
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(row).toHaveCount(0)
}

test('approving, editing and undoing moves the badge through the three states', async ({ page }) => {
  await openSampleModel(page)
  const badge = page.getByTestId('approval-state')

  // Start from a clean slate in case an earlier run left an approval behind.
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
  await manage.getByRole('button', { name: 'Add blueprint' }).click()
  await expect(manage.getByTestId('blueprint-row').filter({ hasText: blueprintName })).toBeVisible()
  await page.keyboard.press('Escape')

  // Two blueprints: the switcher appears and selects the new one.
  const switcher = page.getByTestId('blueprint-switcher')
  await expect(switcher).toBeVisible()
  await switcher.click()
  await page.getByRole('menuitemradio', { name: blueprintName }).click()
  await expect(switcher).toContainText(blueprintName)
  await expect(page).toHaveURL(/blueprint=\d+/)

  // The system context dialog's blueprint select is preset to the switcher's blueprint.
  await page.getByRole('button', { name: 'Open system context' }).click()
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
