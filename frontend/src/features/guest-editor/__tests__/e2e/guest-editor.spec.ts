import { test, expect } from '@playwright/test'
import path from 'path'
import { fileURLToPath } from 'url'

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')
const GUEST_URL = '/guest'

// Playwright cannot drive showOpenFilePicker (a native dialog). The fallback
// <input type="file"> fires a filechooser event instead, so the File System
// Access API is removed before the page loads.
async function stubFileSystemAccess(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showOpenFilePicker
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker
  })
}

async function openFixture(page: import('@playwright/test').Page, name: string) {
  const fileChooserPromise = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: 'Open' }).click()
  const fileChooser = await fileChooserPromise
  await fileChooser.setFiles(path.join(FIXTURES, name))
}

// ---------------------------------------------------------------------------
// 1. A guest editor file: nodes, numbered threats with several targets
// ---------------------------------------------------------------------------

test.describe('guest editor file', () => {
  test('opens a guest file and shows its threats with numbers and targets', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    await openFixture(page, 'valid-diagram.cdx.json')

    await expect(page.locator('text=Web Server').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Database').first()).toBeVisible({ timeout: 5_000 })
    // A file the guest editor wrote opens without warnings or hidden content.
    await expect(page.getByTestId('guest-file-notices')).toHaveCount(0)

    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await expect(page.getByTestId('guest-all-threats')).toBeVisible({ timeout: 10_000 })

    // Every threat, with its number
    await expect(page.getByTestId('guest-threat-row')).toHaveCount(4)
    await expect(page.locator('text=T1').first()).toBeVisible()
    await expect(page.locator('text=SQL Injection')).toBeVisible()

    // Zones and boundaries are targets too
    await page.locator('text=Core network').first().click()
    await expect(page.locator('text=Lateral movement in the core network')).toBeVisible({ timeout: 5_000 })
    await page.locator('text=Internet edge').first().click()
    await expect(page.locator('text=Session hijacking')).toBeVisible({ timeout: 5_000 })

    // A whole-system threat
    await page.getByTestId('guest-whole-system').click()
    await expect(page.locator('text=No backup tested')).toBeVisible({ timeout: 5_000 })

    // A countermeasure linked to two threats
    await page.locator('text=Web Server').first().click()
    await page.locator('text=SQL Injection').click()
    await expect(page.locator('text=Input Validation')).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=Short-lived tokens')).toBeVisible()
    await expect(page.locator('text=also mitigates T2')).toBeVisible()
  })
})

// ---------------------------------------------------------------------------
// 2. Import error UX: invalid files show toast errors
// ---------------------------------------------------------------------------

test.describe('import error handling', () => {
  test('shows error toast for non-JSON file', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise

    await fileChooser.setFiles({
      name: 'bad-file.json',
      mimeType: 'application/json',
      buffer: Buffer.from('this is not json {{{'),
    })

    await expect(page.locator('text=Could not parse file as JSON')).toBeVisible({ timeout: 5_000 })
  })

  test('shows error toast for non-CycloneDX JSON file', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    const fileChooserPromise = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Open' }).click()
    const fileChooser = await fileChooserPromise

    await fileChooser.setFiles({
      name: 'not-cyclonedx.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ name: 'just a regular json file' })),
    })

    await expect(page.locator("text=must have a 'specFormat' field")).toBeVisible({ timeout: 5_000 })
  })
})

// ---------------------------------------------------------------------------
// 3. A backend export: the shared reference fixture opens on its canvas, with
//    the elements it does not show reported on screen and kept for the file
// ---------------------------------------------------------------------------

test.describe('backend export import', () => {
  test('opens the shared fixture and lists what is not on the diagram', async ({ page }) => {
    await stubFileSystemAccess(page)
    await page.goto(GUEST_URL)
    await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

    await openFixture(page, 'backend-export.cdx.json')

    await expect(page.locator('.react-flow__node:has-text("API")').first()).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('.react-flow__node:has-text("DMZ")').first()).toBeVisible({ timeout: 5_000 })

    // Warnings are on screen, not in the console (plan 11.9)
    await expect(page.getByTestId('guest-hidden-notice')).toContainText('12 elements of the blueprint are not on the diagram')
    await expect(page.getByTestId('guest-import-warnings')).toContainText('Some of this file could not be read as it was')
    await page.getByRole('button', { name: 'Dismiss file warnings' }).click()
    await expect(page.getByTestId('guest-import-warnings')).toHaveCount(0)

    await page.getByRole('button', { name: 'Analyze Threats' }).click()
    await expect(page.getByTestId('guest-all-threats')).toBeVisible({ timeout: 10_000 })
    await expect(page.getByTestId('guest-threat-row')).toHaveCount(3)

    await page.locator('text=API').first().click()
    await expect(page.locator('text=SQL injection')).toBeVisible({ timeout: 5_000 })
    await expect(page.locator('text=also targets 1 element not on the diagram')).toBeVisible()
    await page.locator('text=SQL injection').click()
    await expect(page.locator('text=Parameterised queries')).toBeVisible({ timeout: 5_000 })
  })
})
