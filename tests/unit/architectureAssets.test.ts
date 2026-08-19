/** The Architecture page's SVGs are byte-copies of the generated originals in
 * docs/. If the diagrams are regenerated, re-copy and this test enforces it:
 *
 *   python3 docs/generate_architecture.py && python3 docs/generate_request_flow.py
 *   cp docs/architecture.svg docs/request-flow.svg web/src/assets/
 *
 * Same anti-drift philosophy as the business-flows freshness test: the web
 * copy must never silently diverge from the docs source of truth.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const repo = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

for (const name of ['architecture.svg', 'request-flow.svg']) {
  test(`web copy of ${name} matches docs original`, () => {
    const docsCopy = readFileSync(join(repo, 'docs', name))
    const webCopy = readFileSync(join(repo, 'web', 'src', 'assets', name))
    assert.ok(
      docsCopy.equals(webCopy),
      `${name} drifted — run: cp docs/${name} web/src/assets/${name}`,
    )
  })
}
