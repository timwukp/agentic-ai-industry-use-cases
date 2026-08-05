/**
 * Tool-call extraction, run against real captured invoke streams.
 *
 *   node --test tests/unit/toolTrace.test.ts
 *
 * Two fixtures, both real, neither written by hand:
 *
 *   harness_stream_with_tools.json    — a healthy finance invoke: two successful
 *                                       gateway calls whose payloads are the very
 *                                       numbers the reply then quotes.
 *   harness_stream_unknown_tool.json  — the outage capture: 166 events, 7 tool
 *                                       calls, 6 of them "Unknown tool" errors.
 *
 * The second fixture is what makes this suite worth having. During that outage
 * the agent wrote a confident market summary with invented index levels, so a
 * chart panel that drew from *attempted* tool calls, or that ignored result
 * status, would have rendered a chart of nothing next to fabricated prose. The
 * assertions therefore centre on what must be REFUSED: failed calls, non-JSON
 * bodies, and results whose name cannot be established.
 *
 * The correlation being tested is not obvious: `delta.toolResult` carries neither
 * a tool name nor a toolUseId, so the name is only recoverable via
 * contentBlockIndex → toolUseId → name. Block indexes are reused within a single
 * turn, which is the failure mode most likely to attribute one tool's payload to
 * another tool's name.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createToolTrace, bareToolName, type ToolCall } from '../../web/src/lib/toolTrace.ts'

function load(name: string): unknown[] {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'),
  ) as unknown[]
}

/** Runs a whole stream through the collector the way ChatPanel does. */
function collect(events: unknown[]): ToolCall[] {
  const calls: ToolCall[] = []
  const trace = createToolTrace((call) => calls.push(call))
  for (const event of events) trace.push(event)
  trace.flush()
  return calls
}

const healthy = load('harness_stream_with_tools.json')
const broken = load('harness_stream_unknown_tool.json')

test('the fixtures are the real captures, not stubs', () => {
  // Both loops below would pass trivially on an empty or truncated fixture.
  assert.ok(healthy.length > 20, `healthy fixture has only ${healthy.length} events`)
  assert.ok(broken.length > 100, `broken fixture has only ${broken.length} events`)
})

test('successful gateway calls are extracted with their payloads', () => {
  const calls = collect(healthy)
  assert.equal(calls.length, 2, `expected 2 tool calls, got ${calls.map((c) => c.name)}`)

  const overview = calls.find((c) => c.tool === 'get_market_overview')
  assert.ok(overview, 'market overview call not found')
  assert.equal(overview.name, 'market-data___get_market_overview')

  // The decisive assertion: the payload is the parsed tool output, so the panel
  // can plot the exact number the reply quotes.
  const indices = (overview.payload as { indices: Record<string, { value: number }> }).indices
  assert.equal(typeof indices.SP500.value, 'number')

  const sectors = calls.find((c) => c.tool === 'get_sector_performance')
  assert.ok(sectors, 'sector performance call not found')
  assert.ok(
    Array.isArray((sectors.payload as { sectors: unknown[] }).sectors),
    'sector payload should have parsed into an array',
  )
})

test('a payload split across several delta events is reassembled', () => {
  // The sector payload arrives in two chunks in this capture; concatenating in
  // the wrong order, or dropping a chunk, yields invalid JSON and no call at all.
  const chunkEvents = broken.concat(healthy).filter((event) => {
    const delta = (event as { delta?: { toolResult?: unknown } }).delta
    return Array.isArray(delta?.toolResult)
  })
  assert.ok(chunkEvents.length > 2, 'fixtures should contain multi-chunk results')

  const sectors = collect(healthy).find((c) => c.tool === 'get_sector_performance')!
  const list = (sectors.payload as { sectors: Array<Record<string, unknown>> }).sectors
  // 11 sectors only survive if both chunks were joined; the first chunk alone
  // ends mid-object.
  assert.equal(list.length, 11)

  // Asserting the row count is not enough, and the reason is subtle enough to be
  // worth writing down. The chunk boundary in this capture falls inside a key
  // name ("...dai" + "ly_change_pct..."), so joining the chunks with a separator
  // still yields *valid JSON* — just with a key called "dai ly_change_pct". Row
  // count, array length and the intact `name` key all survive that corruption;
  // only checking the field that straddles the boundary catches it.
  for (const [i, row] of list.entries()) {
    assert.equal(
      typeof row.daily_change_pct,
      'number',
      `sector ${i} lost daily_change_pct — the chunk boundary was not joined cleanly`,
    )
  }
})

test('failed tool calls are refused', () => {
  // The outage stream. Every gateway attempt came back status=error with the body
  // "Unknown tool: ...". Extracting any of them would put an empty chart beside a
  // reply full of invented numbers.
  const calls = collect(broken)
  assert.equal(
    calls.length,
    0,
    `expected no extracted calls from the outage stream, got ${JSON.stringify(
      calls.map((c) => c.name),
    )}`,
  )
})

test('an errored result is refused even when its body is valid JSON', () => {
  // The outage stream alone does not prove the status check works: its error
  // bodies were the bare string "Unknown tool: ...", which the JSON.parse guard
  // rejects anyway. Deleting the status check therefore passed every other test
  // in this file. A gateway that reports failure with a JSON body — a Lambda
  // timeout or a 5xx envelope — is the case that distinguishes them, and its
  // payload must not be charted next to a reply the model wrote without it.
  const calls = collect([
    { contentBlockIndex: 0, start: { toolUse: { name: 't___get_market_overview', toolUseId: 'a' } } },
    { contentBlockIndex: 0 },
    { contentBlockIndex: 0, start: { toolResult: { status: 'error', toolUseId: 'a' } } },
    {
      contentBlockIndex: 0,
      delta: { toolResult: [{ text: '{"message":"Task timed out after 30.00 seconds"}' }] },
    },
    { contentBlockIndex: 0 },
  ])
  assert.deepEqual(calls, [], 'an error status must be refused regardless of body')
})

test('a non-JSON tool body is refused', () => {
  // `skills` succeeds and returns Markdown. It is the one tool that reliably
  // works, so treating its body as data would mean a broken deploy still yields
  // a "successful" extraction.
  const calls = collect([
    { contentBlockIndex: 0, start: { toolUse: { name: 'skills', toolUseId: 'a' } } },
    { contentBlockIndex: 0 },
    { contentBlockIndex: 0, start: { toolResult: { status: 'success', toolUseId: 'a' } } },
    { contentBlockIndex: 0, delta: { toolResult: [{ text: '# Finance Analysis\n\n1. Fetch' }] } },
    { contentBlockIndex: 0 },
  ])
  assert.deepEqual(calls, [])
})

test('a result whose toolUse was never seen is refused', () => {
  // Without the name there is no way to pick a recognizer, and guessing from the
  // payload shape is exactly the confident-but-wrong behaviour to avoid.
  const calls = collect([
    { contentBlockIndex: 0, start: { toolResult: { status: 'success', toolUseId: 'ghost' } } },
    { contentBlockIndex: 0, delta: { toolResult: [{ text: '{"sectors":[]}' }] } },
    { contentBlockIndex: 0 },
  ])
  assert.deepEqual(calls, [])
})

test('a block index reused within one turn does not cross-attribute payloads', () => {
  // The real hazard. Index 0 carries a toolUse, then a toolResult, then assistant
  // text — and index 0 is reused for a *second* tool later in the same turn. If
  // per-index state were not cleared, tool B's payload would be filed under tool
  // A's name and the panel would chart the wrong data under the right title.
  const calls = collect([
    { contentBlockIndex: 0, start: { toolUse: { name: 'target___tool_a', toolUseId: 'a' } } },
    { contentBlockIndex: 0 },
    { contentBlockIndex: 0, start: { toolResult: { status: 'success', toolUseId: 'a' } } },
    { contentBlockIndex: 0, delta: { toolResult: [{ text: '{"which":"a"}' }] } },
    { contentBlockIndex: 0 },
    { contentBlockIndex: 0, start: { toolUse: { name: 'target___tool_b', toolUseId: 'b' } } },
    { contentBlockIndex: 0 },
    { contentBlockIndex: 0, start: { toolResult: { status: 'success', toolUseId: 'b' } } },
    { contentBlockIndex: 0, delta: { toolResult: [{ text: '{"which":"b"}' }] } },
    { contentBlockIndex: 0 },
  ])
  assert.equal(calls.length, 2)
  assert.deepEqual(
    calls.map((c) => [c.tool, (c.payload as { which: string }).which]),
    [
      ['tool_a', 'a'],
      ['tool_b', 'b'],
    ],
  )
})

test('concurrent calls on different block indexes stay separate', () => {
  // The healthy capture does exactly this: two tools run in parallel on indexes
  // 0 and 1, and their result deltas interleave.
  const calls = collect(healthy)
  assert.equal(new Set(calls.map((c) => c.tool)).size, calls.length, 'names should be distinct')
})

test('flush releases a block that never received its stop event', () => {
  // A stream cut short mid-block — the panel should still get the completed
  // payload rather than silently dropping it.
  const calls = collect([
    { contentBlockIndex: 0, start: { toolUse: { name: 't___tool', toolUseId: 'a' } } },
    { contentBlockIndex: 0, start: { toolResult: { status: 'success', toolUseId: 'a' } } },
    { contentBlockIndex: 0, delta: { toolResult: [{ text: '{"ok":true}' }] } },
    // no stop event
  ])
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0].payload, { ok: true })
})

test('the gateway target prefix is stripped to the bare tool name', () => {
  // Recognizers key on the bare name so one entry covers a tool whatever its
  // gateway target is called — the outage showed target naming is not stable.
  assert.equal(bareToolName('market-data___get_market_overview'), 'get_market_overview')
  assert.equal(bareToolName('skills'), 'skills')
  // Only the LAST separator is the boundary; a target containing "___" must not
  // eat part of the tool name.
  assert.equal(bareToolName('a___b___get_thing'), 'get_thing')
})

test('malformed events do not throw', () => {
  // Stream payloads are parsed from the wire; the collector must tolerate
  // anything rather than take the chat panel down.
  const junk = [null, undefined, 'text', 42, {}, { contentBlockIndex: 'x' }, { start: {} }]
  assert.deepEqual(collect(junk), [])
})

/*
 * Mutation results (each applied to web/src/lib/toolTrace.ts, run, reverted):
 *
 *  1. `pending.status !== 'success'` check removed        → 1 failure
 *  2. `finish()` no longer clears per-index state         → 3 failures
 *  3. chunks joined with ' ' instead of ''                → 1 failure
 *  4. `if (!name) return` dropped                         → 1 failure
 *  5. JSON.parse failure returns `{}` instead of skipping → 2 failures
 *  6. `bareToolName` uses indexOf instead of lastIndexOf  → 1 failure
 *  7. `flush()` body emptied                              → 1 failure
 *
 * All seven caught — but two of them only after the tests were fixed, and both
 * gaps are the same mistake in two disguises: asserting a *proxy* for the thing
 * that matters instead of the thing itself.
 *
 *   - #1 initially survived. The outage fixture's error bodies are the bare
 *     string "Unknown tool: ...", which the JSON.parse guard already rejects, so
 *     "failed tool calls are refused" passed with the status check deleted. Fixed
 *     by adding an errored result whose body IS valid JSON.
 *   - #3 initially survived. The chunk boundary in the real capture falls inside
 *     a key name, so joining with a separator still parses — into an object with
 *     a key called "dai ly_change_pct". Array length was unchanged, so the row
 *     count assertion held. Fixed by asserting on the field that straddles the
 *     boundary.
 */
