/**
 * The AI Assistant's starter questions — the empty-pane entry point.
 *
 * Unit tests (tests/unit/test_starter_prompts.py) already prove the prompt text
 * names real entities and valid enums. What only a browser can prove is that the
 * buttons render per industry, that clicking one actually sends (rather than
 * merely prefilling), and that the pane clears once a conversation exists — a
 * starter list still sitting above a live thread would be a layout bug.
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

// One representative per harness. Counts come from starterPrompts.ts; the unit
// suite pins the file-vs-parse totals, so this only asserts "at least 3 render".
const INDUSTRIES = [
  'finance',
  'healthcare-medical',
  'insurance-claims',
  'retail-inventory',
  'manufacturing-maintenance',
  'real-estate-valuation',
];

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

for (const industryId of INDUSTRIES) {
  test(`${industryId} shows starter questions in an empty chat`, async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto(`/${industryId}/chat`);

    const pane = page.locator('[data-testid="starter-pane"]').locator('visible=true');
    await expect(pane.first()).toBeVisible({ timeout: 30_000 });

    const starters = pane.first().locator('[data-testid="starter-prompt"]');
    const count = await starters.count();
    expect(count, `${industryId} rendered ${count} starters`).toBeGreaterThanOrEqual(3);

    // Each button carries a label AND the prompt itself, so a visitor can see
    // what will be sent before committing.
    const first = starters.first();
    await expect(first).toBeVisible();
    const text = (await first.innerText()).trim();
    expect(text.length, `${industryId} first starter is blank`).toBeGreaterThan(10);

    // Suffixed by project: both run the same path, and without this the mobile
    // pass silently overwrote the desktop capture — the layout defect this
    // feature shipped with was a mobile-only clip, so one file per viewport is
    // the whole point of taking them.
    await page.screenshot({
      path: `screenshots/${industryId}-starters-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });
}

test('clicking a starter sends it and the pane disappears', async ({
  page,
}, testInfo) => {
  await login(page);
  await page.goto('/finance/chat');

  const pane = page.locator('[data-testid="starter-pane"]').locator('visible=true').first();
  await expect(pane).toBeVisible({ timeout: 30_000 });

  const starter = pane.locator('[data-testid="starter-prompt"]').first();
  const promptText = (await starter.innerText()).trim();
  await starter.click();

  // The click sends: a user bubble appears without anyone pressing Enter.
  const userBubble = page.locator('[data-role="user"]').last();
  await expect(userBubble).toBeVisible({ timeout: 30_000 });
  // The bubble shows the prompt, not the short label — the label is scan text.
  const sent = (await userBubble.innerText()).trim();
  expect(sent.length).toBeGreaterThan(20);
  expect(promptText).toContain(sent);

  // …and the agent answers it.
  const assistant = page.locator('[data-role="assistant"]').last();
  await expect(assistant).toBeVisible({ timeout: 60_000 });
  await expect(assistant).not.toHaveText('', { timeout: 60_000 });

  // Starters belong to an empty pane only.
  await expect(
    page.locator('[data-testid="starter-pane"]').locator('visible=true'),
  ).toHaveCount(0);

  await page.screenshot({
    path: `screenshots/starter-sent-${testInfo.project.name}.png`,
    fullPage: true,
  });
});

test('starters differ per industry', async ({ page }) => {
  await login(page);

  const read = async (industryId: string) => {
    await page.goto(`/${industryId}/chat`);
    const pane = page
      .locator('[data-testid="starter-pane"]')
      .locator('visible=true')
      .first();
    await expect(pane).toBeVisible({ timeout: 30_000 });
    return pane.locator('[data-testid="starter-prompt"]').allInnerTexts();
  };

  // A single shared list would be a worse demo than none: it would tell a
  // manufacturing visitor to ask about SKUs.
  const retail = await read('retail-inventory');
  const manufacturing = await read('manufacturing-maintenance');
  expect(retail.join('|')).not.toEqual(manufacturing.join('|'));
  expect(retail.join(' ')).toContain('SKU-');
  expect(manufacturing.join(' ')).toContain('EQ-');
});
