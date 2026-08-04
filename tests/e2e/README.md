# E2E tests (Playwright)

Run against the deployed CloudFront URL after `make deploy-web`.

```bash
cd tests/e2e
npm install
BASE_URL=https://<cloudfront-domain> E2E_EMAIL=<user> E2E_PASSWORD=<pass> npx playwright test
```

Covers: login → streaming chat reply renders → dashboard shows live API data →
mobile viewport layout. Screenshots land in `tests/e2e/screenshots/`.
