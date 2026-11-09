import { test, expect } from '@playwright/test'

// #563: a long diagram title ran under the controls beside it. 1300px wide is the
// width of the report's screenshots, and past `xl` (1280px), where the header also
// shows undo/redo and the notation select.
test.use({ viewport: { width: 1300, height: 800 } })

const LONG_TITLE = 'AWS E-Commerce / AI Order Processing Threat Model With A Very Long Name'

test('a long title is cut off before the context button', async ({ page }) => {
  await page.goto('/guest')
  await expect(page.locator('text=Components')).toBeVisible({ timeout: 10_000 })

  await page.locator('h1').first().click()
  await page.keyboard.press('ControlOrMeta+A')
  await page.keyboard.type(LONG_TITLE)
  await page.keyboard.press('Enter')

  const title = page.locator('h1', { hasText: 'AWS E-Commerce' })
  await expect(title).toBeVisible()
  const contextButton = page.getByRole('button', { name: 'Add / Edit Context' })

  const titleBox = await title.boundingBox()
  const buttonBox = await contextButton.boundingBox()
  if (!titleBox || !buttonBox) throw new Error('title or context button not laid out')
  expect(titleBox.x + titleBox.width).toBeLessThanOrEqual(buttonBox.x)
  // Cut off with an ellipsis, not wrapped: the text is wider than its box.
  expect(await title.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true)
})
