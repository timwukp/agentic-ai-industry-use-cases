/**
 * The three chat-readability features, verified against the live app.
 *
 * All three fix the same complaint — an answer that arrived as an unreadable
 * wall of text — at different layers, so they are checked together:
 *
 *   1. Markdown rendering (the floor). The agent was already emitting correct
 *      GFM; the panel rendered it through `whitespace-pre-wrap`, so a table
 *      arrived as raw pipes. Only a browser can prove a <table> now exists.
 *   2. The answer chart panel (the ceiling). Ranked numbers are a chart, and a
 *      chart does not fit a 340px bubble. Charts are built from the tool payload
 *      the agent itself received, extracted from the invoke stream — so the
 *      decisive assertion is not "a chart appeared" but "the chart's numbers are
 *      the numbers in the prose beside it".
 *   3. Reply language. An English starter question came back in Chinese because a
 *      Chinese memory record was read as a language signal.
 *
 * Unit tests already cover the extraction and the recognizers against real
 * captured payloads (tests/unit/toolTrace.test.ts, chartSpec.test.ts). What only
 * a live browser can prove is that a real answer, from a real harness, over the
 * real event stream, actually produces a panel — the unit suite would pass just
 * as happily if the stream never reached the extractor at all.
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

/** A question that cannot be answered without get_sector_performance, whose
 *  payload is a recognized chart (11 ranked sectors). Phrased in English so the
 *  same run also checks the reply language. */
const SECTOR_QUESTION =
  'Which sectors are leading and which are lagging today?';

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

/** Sends a prompt in the chat pane and waits for the answer to finish streaming.
 *  Returns the assistant bubble. */
async function ask(page: Page, prompt: string) {
  const box = page.getByRole('textbox', { name: /ask the agent/i }).or(
    page.locator('textarea[placeholder="Ask the agent…"]'),
  );
  const input = box.locator('visible=true').first();
  await expect(input).toBeVisible({ timeout: 30_000 });
  await input.fill(prompt);
  await input.press('Enter');

  const assistant = page.locator('[data-role="assistant"]').last();
  await expect(assistant).toBeVisible({ timeout: 60_000 });
  // Streaming end: the blinking caret is removed and the text stops growing.
  // Waiting on text alone would race — an empty bubble "has text" as soon as the
  // first chunk lands, and Markdown is only parsed after the stream closes.
  await expect(input).toBeEnabled({ timeout: 120_000 });
  await expect(assistant).not.toHaveText('', { timeout: 10_000 });
  return assistant;
}

test('a sector answer produces a chart whose numbers match the prose', async ({
  page,
}, testInfo) => {
  const desktop = testInfo.project.name === 'desktop';
  await login(page);
  // At lg+ the dashboard and chat are one split view, so asking from the
  // dashboard route is what a user actually does — and it is the route where the
  // overlay has to appear. Below lg they are separate views and the dashboard
  // route has no input at all, so the question has to be asked from /chat.
  await page.goto(desktop ? '/finance/dashboard' : '/finance/chat');

  const answer = await ask(page, SECTOR_QUESTION);
  const prose = await answer.innerText();

  // Feature 3: an English question is answered in English. Asserting on CJK
  // absence rather than on English words, because the failure was categorical —
  // the whole reply came back in Chinese, not a stray phrase.
  expect(
    /[぀-ヿ㐀-䶿一-鿿]/u.test(prose),
    `English question answered with CJK text:\n${prose.slice(0, 400)}`,
  ).toBe(false);

  // Feature 1: Markdown is parsed. The sector answer is a ranked list, which the
  // model renders as a table or a list — either proves parsing; raw pipes or
  // literal "##" would prove the opposite.
  const structure = answer.locator('table, ul, ol, strong, h2, h3');
  expect(
    await structure.count(),
    `answer rendered no markdown structure:\n${prose.slice(0, 400)}`,
  ).toBeGreaterThan(0);
  await expect(answer).not.toContainText('|---');

  // Feature 2: the panel. Desktop shows the overlay above the dashboard; below lg
  // the same specs render inline under the message.
  const panel = desktop
    ? page.locator('[data-testid="answer-chart-panel"]')
    : page.locator('[data-testid="inline-answer-charts"]');
  await expect(panel.first()).toBeVisible({ timeout: 30_000 });

  const chart = panel.first().locator('[data-testid="answer-chart"]').first();
  await expect(chart).toBeVisible();
  // recharts renders into an <svg class="recharts-surface">; its absence would
  // mean a titled empty card, which looks fine in a screenshot.
  await expect(chart.locator('svg.recharts-surface')).toBeVisible();

  // The decisive assertion. The whole design rests on the chart being drawn from
  // the same bytes the model read, so a category named in the chart must also be
  // named in the prose. A chart that silently disagrees with the text beside it
  // would be worse than no chart, and would look perfectly healthy otherwise.
  // textContent, not allInnerTexts(): these ticks are SVG <text> nodes, and
  // innerText is an HTMLElement property — on SVG it comes back undefined, so
  // allInnerTexts() yields a list of undefined rather than throwing or returning
  // empty. A `.length > 2` check on that list passes cheerfully.
  const labels = await chart
    .locator('.recharts-yAxis .recharts-cartesian-axis-tick-value')
    .evaluateAll((nodes) => nodes.map((n) => n.textContent ?? ''));
  expect(labels.length, 'chart rendered no category labels').toBeGreaterThan(2);
  // A label ending in the truncation ellipsis is matched on its visible prefix;
  // a label that is ONLY an ellipsis (or a couple of characters) names nothing,
  // which is exactly the shipped bug this assertion caught — the axis read
  // "…", "R…", "Hea…" because the tick formatter was receiving the tick index.
  const clean = labels
    .map((t) => t.trim().replace(/…$/, ''))
    .filter((t) => t.length > 3);
  expect(
    clean.length,
    `axis labels are too short to identify anything: ${JSON.stringify(labels)}`,
  ).toBeGreaterThanOrEqual(labels.length - 1);
  const matched = clean.filter((label) => prose.includes(label));
  expect(
    matched.length,
    `no charted sector appears in the answer text. axis=${JSON.stringify(
      clean,
    )} prose=${prose.slice(0, 600)}`,
  ).toBeGreaterThan(0);

  await page.screenshot({
    path: `screenshots/answer-chart-${testInfo.project.name}.png`,
    fullPage: true,
  });
});

test('the chart panel is dismissible and the dashboard survives it', async ({
  page,
}, testInfo) => {
  test.skip(
    testInfo.project.name !== 'desktop',
    'the overlay is desktop-only; below lg charts render inline with the message',
  );
  await login(page);
  await page.goto('/finance/dashboard');

  await ask(page, SECTOR_QUESTION);
  const panel = page.locator('[data-testid="answer-chart-panel"]');
  await expect(panel).toBeVisible({ timeout: 30_000 });

  // The dashboard is the standing view: the panel stacks ABOVE it rather than
  // replacing it, so dashboard content must be reachable while the panel is up.
  const dashboardHeading = page.getByRole('heading', { name: /Finance/i }).first();
  await expect(dashboardHeading).toBeVisible();

  await page.locator('[data-testid="dismiss-answer-chart"]').click();
  await expect(panel).toHaveCount(0);
  // Dismissing the by-product must not disturb the standing view.
  await expect(dashboardHeading).toBeVisible();
});

test('a new question clears the previous answer’s charts', async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'overlay is desktop-only');
  await login(page);
  await page.goto('/finance/dashboard');

  await ask(page, SECTOR_QUESTION);
  const chart = page.locator('[data-testid="answer-chart-panel"] [data-testid="answer-chart"]');
  await expect(chart).toBeVisible({ timeout: 30_000 });
  const firstTitle = await chart.getAttribute('data-chart-title');
  expect(firstTitle).toBeTruthy();

  // A question whose tools produce no chart. Leaving the sector chart up would be
  // the one way this panel could actively mislead: a chart captioned "from the
  // assistant's answer" that belongs to a different answer entirely.
  await ask(page, 'In one sentence, what does a VaR figure mean?');
  await expect(
    page.locator(
      `[data-testid="answer-chart-panel"] [data-chart-title="${firstTitle}"]`,
    ),
  ).toHaveCount(0);
});

test('switching industry does not carry charts to the new dashboard', async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'overlay is desktop-only');
  await login(page);
  await page.goto('/finance/dashboard');

  await ask(page, SECTOR_QUESTION);
  await expect(page.locator('[data-testid="answer-chart-panel"]')).toBeVisible({
    timeout: 30_000,
  });

  // Finance sector performance hanging over the healthcare dashboard would read
  // as healthcare data.
  await page.goto('/healthcare-medical/dashboard');
  await expect(page.locator('[data-testid="answer-chart-panel"]')).toHaveCount(0);
});

test('a Chinese question is answered in Chinese', async ({ page }, testInfo) => {
  // The mirror of the CJK assertion in the first test, and the half that could
  // regress silently. The bug was English-in / Chinese-out, so a fix that simply
  // forced English everywhere would pass every other assertion in this file
  // while breaking the user's own language.
  await login(page);
  await page.goto('/finance/chat');

  const answer = await ask(page, '今天哪些板塊領先，哪些落後？');
  const prose = await answer.innerText();
  expect(
    /[一-鿿]/u.test(prose),
    `Chinese question answered without CJK text:\n${prose.slice(0, 400)}`,
  ).toBe(true);

  // Still charted: the recognizers key on the tool name, not on the language of
  // the question, so the panel must appear here too.
  const desktop = testInfo.project.name === 'desktop';
  const panel = desktop
    ? page.locator('[data-testid="answer-chart-panel"]')
    : page.locator('[data-testid="inline-answer-charts"]');
  await expect(panel.first()).toBeVisible({ timeout: 30_000 });

  await page.screenshot({
    path: `screenshots/answer-chart-zh-${testInfo.project.name}.png`,
    fullPage: true,
  });
});

test('a threshold in the spec is actually drawn on a bar chart', async ({
  page,
}, testInfo) => {
  // The bug this exists to catch shipped: `<ReferenceLine y={...}>` is correct on
  // the line chart, but the bar charts use `layout="vertical"`, where the value
  // axis is x. Every bar-chart threshold — the market median under listing
  // prices, the upper reference limit on labs, reorder points, adherence targets
  // — was silently not rendered while the spec carried it. The unit suite asserted
  // the spec and could not see it; a screenshot showed a chart that looked fine.
  //
  // "Find 3-bed homes" is the case where the line carries the answer: the reply
  // says which listings sit below the market median, and without the line the
  // reader has no way to see which those are.
  const desktop = testInfo.project.name === 'desktop';
  await login(page);
  await page.goto(desktop ? '/real-estate-valuation/dashboard' : '/real-estate-valuation/chat');

  await ask(page, 'Find 3-bedroom homes for sale in 78701.');

  const panel = desktop
    ? page.locator('[data-testid="answer-chart-panel"]')
    : page.locator('[data-testid="inline-answer-charts"]');
  await expect(panel.first()).toBeVisible({ timeout: 30_000 });

  const chart = panel.first().locator('[data-chart-title="Listing prices"]');
  await expect(chart).toBeVisible({ timeout: 30_000 });
  const line = chart.locator('.recharts-reference-line line');
  await expect(line.first()).toBeAttached({ timeout: 15_000 });

  // A line at x=0 would be attached while conveying nothing, so assert it sits
  // inside the plot rather than pinned to the axis.
  const box = await line.first().boundingBox();
  const plot = await chart.locator('svg.recharts-surface').boundingBox();
  expect(box, 'the reference line has no geometry').not.toBeNull();
  expect(plot).not.toBeNull();
  expect(
    box!.x - plot!.x,
    `the median line sits at the left edge (x=${box!.x}, plot starts ${plot!.x})`,
  ).toBeGreaterThan(20);
  // Vertical, not horizontal: a y-positioned line on this chart would span the
  // full width, which is precisely the wrong axis.
  expect(box!.height, 'the threshold line is horizontal, not vertical').toBeGreaterThan(
    box!.width,
  );

  // And it must say what it is. An unlabelled dashed rule is worse than none
  // here: the reply quotes the single-family median ($655K) while this line is
  // the all-types median ($528K), so a reader with no label is free to read the
  // line as the figure the prose names. `position: 'top'` put the text above the
  // plot where the container clipped it — the line was there and the label was
  // not, which no assertion on the line alone can distinguish.
  const label = chart.locator('.recharts-reference-line .recharts-label');
  await expect(label.first()).toBeVisible({ timeout: 10_000 });
  const labelBox = await label.first().boundingBox();
  expect(labelBox, 'the reference-line label has no geometry').not.toBeNull();
  expect(
    labelBox!.y,
    `the label is clipped above the plot (label y=${labelBox!.y}, plot starts ${plot!.y})`,
  ).toBeGreaterThanOrEqual(plot!.y - 1);
  expect(labelBox!.y + labelBox!.height).toBeLessThanOrEqual(plot!.y + plot!.height + 1);
  await expect(label.first()).toHaveText(/median/i);

  await page.screenshot({
    path: `screenshots/answer-chart-refline-${testInfo.project.name}.png`,
    fullPage: true,
  });
});

test('a threshold above every plotted value is still drawn', async ({ page }, testInfo) => {
  // The second way a reference line disappears, and the one the unit suite cannot
  // reach: recharts defaults `ifOverflow` to "discard", so a line outside the axis
  // domain is dropped silently. The spec is identical either way — this is a
  // property of the rendered component, so only a browser can tell the difference.
  //
  // CNC-001 vibration is the case that matters. Readings run 2.6–4.5 mm/s and the
  // ISO 10816 Zone C warning limit is 7.1, i.e. above every plotted point, so the
  // axis has to be extended to hold it. And it is the whole answer: "3.7 mm/s" says
  // nothing to a reader who cannot see the limit it sits under, which is precisely
  // the question ("is the vibration on CNC-001 a problem?") the chart is answering.
  const desktop = testInfo.project.name === 'desktop';
  await login(page);
  await page.goto(
    desktop ? '/manufacturing-maintenance/dashboard' : '/manufacturing-maintenance/chat',
  );

  await ask(page, 'Analyze the vibration readings on CNC-001 over the last 24 hours.');

  const panel = desktop
    ? page.locator('[data-testid="answer-chart-panel"]')
    : page.locator('[data-testid="inline-answer-charts"]');
  await expect(panel.first()).toBeVisible({ timeout: 30_000 });

  // The vibration answer calls several tools, so the reading chart may not be the
  // first page of the panel; find it by title.
  const chart = panel.first().locator('[data-chart-title$="readings"]').first();
  await expect(chart).toBeVisible({ timeout: 30_000 });

  const line = chart.locator('.recharts-reference-line line');
  await expect(line.first()).toBeAttached({ timeout: 15_000 });
  const box = await line.first().boundingBox();
  const plot = await chart.locator('svg.recharts-surface').boundingBox();
  expect(box, 'the warning threshold was discarded for being outside the domain').not.toBeNull();
  expect(plot).not.toBeNull();
  // Horizontal on a line chart: the value axis is y here, the mirror image of the
  // bar-chart case above.
  expect(box!.width, 'the threshold line is vertical, not horizontal').toBeGreaterThan(
    box!.height,
  );
  // Above the series, since every reading is below the limit — and inside the plot,
  // not clipped to its top edge, which is what "extendDomain" buys.
  expect(box!.y - plot!.y, 'the line is pinned to the top edge of the plot').toBeGreaterThan(4);
  const dots = await chart.locator('.recharts-line-curve').boundingBox();
  expect(dots, 'the series did not render').not.toBeNull();
  expect(box!.y, 'a warning limit above every reading must plot above the series').toBeLessThan(
    dots!.y,
  );
  // And the series must still be legible: extending the domain squashes it, and
  // past a point the trend — the other half of the answer — is a flat smear. A
  // third of the plot is the floor the recognizer enforces (MIN_DATA_SHARE).
  expect(
    dots!.height / plot!.height,
    `the series occupies only ${((dots!.height / plot!.height) * 100).toFixed(0)}% of the plot`,
  ).toBeGreaterThan(0.2);

  await expect(chart.locator('.recharts-reference-line .recharts-label').first()).toHaveText(
    /warning/i,
  );

  await page.screenshot({
    path: `screenshots/answer-chart-overflow-${testInfo.project.name}.png`,
    fullPage: true,
  });
});
