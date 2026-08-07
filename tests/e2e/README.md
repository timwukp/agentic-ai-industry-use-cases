# E2E tests (Playwright)

Run against the deployed CloudFront URL after `make deploy-web`.

```bash
cd tests/e2e
npm install
BASE_URL=https://<cloudfront-domain> E2E_EMAIL=<user> E2E_PASSWORD=<pass> npx playwright test
```

70 tests across `desktop` and `mobile` projects — 62 assertions plus 8 screenshot captures:

| Spec | Covers |
|---|---|
| `app.spec.ts` | login, and a streamed reply rendering from each of the six harnesses |
| `industry-dash.spec.ts` | for insurance / retail / manufacturing / real-estate: dashboard tiles render values from the live API (not `—` placeholders), and **Ask agent** prefills the chat input |
| `healthcare-dash.spec.ts` | Patient 360 renders, the patient chip switches context, Ask agent prefills |
| `starter-prompts.spec.ts` | each industry's empty chat offers its own starter questions, and clicking one sends it (rather than prefilling) and clears the pane |
| `answer-charts.spec.ts` | the chart panel, markdown rendering, and reply language — see below |
| `eyeball.spec.ts` | full-page screenshots for visual inspection — **not** assertions |

```bash
npx playwright test --grep-invert eyeball   # assertions only
npx playwright test --grep "retail|real-estate"
```

`answer-charts.spec.ts` covers the three chat-readability features together, because all three
address the same complaint (an answer arriving as an unreadable wall of text) at different
layers. Its load-bearing assertion is not "a chart appeared" but that a category named on the
chart's axis also appears in the prose beside it: the charts are built from the tool payload
the agent itself received (`web/src/lib/toolTrace.ts`), and a chart that silently disagreed
with the text next to it would be worse than no chart while looking perfectly healthy.

Two real bugs were caught here that the unit suite could not see. Both were invisible except in
a rendered browser:

- **Axis labels read `…`, `R…`, `Hea…`.** recharts calls a tick formatter with `(value, index)`,
  and the formatter had been written as `shortLabel(value, max = 18)` — so the tick index landed
  in `max` and every label was cut to its own axis position. Nothing threw; the chart drew.
  Now pinned by `tests/unit/chartFormat.test.ts`.
- **The overlay clipped an 11-row chart mid-bar** at its original 45% height cap.

Three tests `skip` on mobile: the overlay is a desktop-only surface, because below `lg` the
dashboard and chat are separate views and the charts render inline under the message instead.

Note the demo user is `demo@example.com` (see `deploy/outputs/demo-user-password.txt`), not a
personal address — passing the wrong one fails every spec at login with
"Incorrect username or password", which reads like an app outage rather than a bad env var.

Screenshots land in `tests/e2e/screenshots/`. Note `outputDir` is that same directory, so a
full run **wipes** it before writing — re-capture with `--grep` rather than expecting old
screenshots to survive. Files that both projects write are suffixed with the project name
(`-desktop` / `-mobile`); without that, the second project to finish overwrites the first,
and the layout bugs worth catching are usually viewport-specific.
