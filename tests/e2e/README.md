# E2E tests (Playwright)

Run against the deployed CloudFront URL after `make deploy-web`.

```bash
cd tests/e2e
npm install
BASE_URL=https://<cloudfront-domain> E2E_EMAIL=<user> E2E_PASSWORD=<pass> npx playwright test
```

44 tests across `desktop` and `mobile` projects:

| Spec | Covers |
|---|---|
| `app.spec.ts` | login, and a streamed reply rendering from each of the six harnesses |
| `industry-dash.spec.ts` | for insurance / retail / manufacturing / real-estate: dashboard tiles render values from the live API (not `—` placeholders), and **Ask agent** prefills the chat input |
| `healthcare-dash.spec.ts` | Patient 360 renders, the patient chip switches context, Ask agent prefills |
| `eyeball.spec.ts` | full-page screenshots for visual inspection — **not** assertions |

```bash
npx playwright test --grep-invert eyeball   # assertions only
npx playwright test --grep "retail|real-estate"
```

Screenshots land in `tests/e2e/screenshots/`. Note `outputDir` is that same directory, so a
full run **wipes** it before writing — re-capture with `--grep` rather than expecting old
screenshots to survive.
