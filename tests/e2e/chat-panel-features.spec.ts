/**
 * Real-browser verification of the chat panel's new capabilities:
 * resize drag, minimize/restore, maximize/restore, and the chat-history
 * save → search → load roundtrip against the live S3-backed API.
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

test('chat panel resizes by dragging and persists the width', async ({ page }) => {
  await login(page);
  const pane = page.locator('[data-chat-mode="normal"]');
  await expect(pane).toBeVisible();
  const before = (await pane.boundingBox())!.width;

  const handle = page.getByTestId('chat-resize-handle');
  const box = (await handle.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x - 150, box.y + box.height / 2, { steps: 10 });
  await page.mouse.up();

  const after = (await pane.boundingBox())!.width;
  expect(after).toBeGreaterThan(before + 100);

  // width persists across reload (localStorage)
  await page.reload();
  await expect(page.locator('[data-chat-mode="normal"]')).toBeVisible();
  const reloaded = (await page.locator('[data-chat-mode="normal"]').boundingBox())!
    .width;
  expect(Math.abs(reloaded - after)).toBeLessThan(8);
});

test('chat panel minimizes to rail and restores; maximizes over dashboard', async ({
  page,
}) => {
  await login(page);

  await page.getByTestId('chat-minimize').click();
  await expect(page.getByTestId('chat-restore')).toBeVisible();
  await expect(page.locator('[data-chat-mode]')).toHaveCount(0);

  await page.getByTestId('chat-restore').click();
  await expect(page.locator('[data-chat-mode="normal"]')).toBeVisible();

  await page.getByTestId('chat-maximize').click();
  const maxed = page.locator('[data-chat-mode="max"]');
  await expect(maxed).toBeVisible();
  // dashboard pane hidden while maximized
  await expect(page.locator('[data-section="market-live"]')).toBeHidden();
  const width = (await maxed.boundingBox())!.width;
  expect(width).toBeGreaterThan(700);

  await page.getByTestId('chat-maximize').click(); // restore
  await expect(page.locator('[data-chat-mode="normal"]')).toBeVisible();
  await expect(page.locator('[data-section="market-live"]')).toBeVisible();
});

test('history: conversation saves, is searchable, and loads back', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await login(page);

  // have a short conversation so there is something to save
  const marker = `history e2e ${Date.now().toString(36)}`;
  const input = page.getByPlaceholder(/ask/i);
  await input.fill(`Reply with exactly: ${marker}`);
  await input.press('Enter');
  await expect(
    page.locator('[data-role="assistant"]').last(),
  ).toContainText(marker, { timeout: 120_000 });

  // wait past the save debounce, then open history
  await page.waitForTimeout(2500);
  await page.getByTestId('history-open').click();
  const drawer = page.getByTestId('history-drawer');
  await expect(drawer).toBeVisible();

  // search for the marker (title = first user message contains it)
  await page.getByTestId('history-search').fill(marker.slice(0, 20));
  const entry = page.getByTestId('history-entry').first();
  await expect(entry).toBeVisible({ timeout: 15_000 });

  // load it back into the window
  await entry.click();
  await expect(drawer).toBeHidden();
  await expect(page.locator('[data-role="user"]').first()).toContainText(
    marker.slice(0, 20),
  );
  await expect(page.locator('[data-role="assistant"]').first()).toContainText(
    marker,
  );
});
