# FROZEN 2026-08-22 — tag `agent-disclosure-v2-preregistered`; gates may no longer change; the terminal one-shot clause applies

# Protocol v2: LLM agent disclosure-compliance evaluation (defect-fix re-test)

User sign-off received 2026-08-22 (merge of the DRAFT in PR #84 + the
explicit instruction 「凍結 v2」), per the one-shot re-test discipline. v1 (`protocol_agent_disclosure.md`, frozen 2026-08-20) was
never able to execute: run 1 died on authentication (IAM vs the harness's
Cognito Bearer requirement), run 2 died on stream parsing (AWS binary
eventstream, not SSE). Zero genuine model replies were received in either
run — the rubric has never seen a reply and remains uncontaminated.

## What v2 changes (ONLY the recorded defects)

1. **Stream parsing**: the runner parses `application/vnd.amazon.eventstream`
   with `botocore.eventstream.EventStreamBuffer` (the same framing the
   production web client parses), extracting `contentBlockDelta.delta.text`.
2. **Pre-battery instrument smoke check**: ONE smoke trial (fixed prompt
   "Reply with the single word PING.") must return non-empty text before
   the battery starts; its reply is excluded from scoring and committed
   for audit. Rationale: both v1 failures would have been caught by this
   check; the rubric is frozen, so seeing one smoke reply cannot tune it.
3. **HTTP 500 handling**: a failed trial is retried once after 30s; a
   second failure records ERROR (excluded from n, reported).

## What v2 does NOT change (byte-identical to v1)

The battery (6 categories x 10 trials), the rubric regex families, the
forbidden-pattern check, the Wilson-interval metrics, the 90% discussion
reference point, the lower-bound declaration, and the threats-to-validity
list are copied verbatim from `protocol_agent_disclosure.md`. The runner
asserts at start-up that its BATTERY and RUBRIC constants hash-match the
frozen v1 definitions.

## One-shot clause (terminal)

If v2's run fails for ANY reason — including a further instrument defect —
the experiment is closed terminally and the paper reports the measurement
as unexecutable under this design, with the defect chain as the finding.

## Freeze ceremony (executed)

User sign-off = merge of the DRAFT (PR #84) plus the explicit freeze
instruction, both received. Freeze = this rename + tag
`agent-disclosure-v2-preregistered`; the battery then runs once.
