# PRISM Theory Scout — deploy path

A scheduled, autonomous research agent that keeps the `research/` pipeline
fed without a human remembering to run it. It executes **Phases 0–2 only**
of [skills/theory-to-production](../../skills/theory-to-production/SKILL.md)
and hard-stops at a `DRAFT_protocol_*.md` pull request: humans freeze, test,
and promote. An empty-handed run (no candidate survives screening) is a valid
outcome; it opens a **micro-PR** appending one rejection line per screened
candidate to `research/rejected_candidates.md` — nothing else — so the shelf
remembers dead candidates and the next cycle cannot re-shop them.

## Architecture

```
EventBridge Scheduler (prism-theory-scout-monthly, cron 0 2 1 * ? * UTC)
  → CodeBuild project prism-theory-scout
      (source = this repo's MAIN branch → the driver that runs is always
       the reviewed, merged one; buildspec.yml in this directory)
    → driver.py → InvokeHarness (data plane, streaming)
        → AgentCore Harness "PrismTheoryScout" (us-east-1)
            model global.anthropic.claude-sonnet-5 · tools: browser,
            code interpreter, skills · skill git-sourced from main ·
            managed memory (SEMANTIC + EPISODIC) · OTel tracing on
```

The agent's write access to GitHub is a fine-grained PAT (this repo only,
Contents + Pull requests R/W) in the harness env var `GITHUB_TOKEN`. Its
system prompt limits use to: create branch, commit blobs/trees, open ONE
pull request. It cannot merge (and the repo's review flow wouldn't let it).

## Files

- `driver.py` — invokes the harness and streams the run into CodeBuild logs.
  Fail-visible: `MARKER run-start/run-end` lines, non-zero exit on an empty
  or broken stream. The boto3 client uses `read_timeout=3900` — it must
  outlive the harness's `timeoutSeconds=3600`, because the agent goes silent
  for minutes during research and the default 60s timeout kills a healthy
  run (observed 2026-08-11). Retries are off: a retry would re-invoke the
  whole session.
- `buildspec.yml` — CodeBuild entry: install boto3, run the driver.
- `deploy_scheduler.sh` — idempotent (re)deploy of the CodeBuild project +
  EventBridge schedule. Assumes the harness and IAM roles exist.

## IAM (least privilege, one role per hop)

| Role | Trusts | May only |
|---|---|---|
| `PrismTheoryScoutHarnessRole` | bedrock-agentcore | invoke the model, run built-in browser/code-interpreter sessions, read/write its own managed memory, emit logs/traces |
| `PrismTheoryScoutDriverRole` | codebuild | write its build logs + `InvokeHarness`/`InvokeAgentRuntime` on the scout's ARNs |
| `PrismTheoryScoutSchedulerRole` | scheduler | `codebuild:StartBuild` on `prism-theory-scout` |

## Operations

- **Manual run**: `HARNESS_ARN=<arn> AWS_REGION=us-east-1 python3 driver.py`
  (or start the CodeBuild project from the console). Runs take 30–60 min.
- **Logs**: CodeBuild build logs carry the full streamed session; the harness
  also delivers app logs + X-Ray traces via CloudWatch log delivery.
- **PAT rotation**: mint a new fine-grained PAT (this repo only, Contents +
  Pull requests R/W, with expiry), then update the harness env var
  `GITHUB_TOKEN` via `UpdateHarness`. On expiry the scout still runs — it
  just can't open PRs, and its findings remain in the CodeBuild logs.
- **Change the prompt/tools/schedule**: harness config changes via
  `UpdateHarness` (each update = new immutable version); schedule/project
  changes via `deploy_scheduler.sh`.

## Validation record (2026-08-11)

- Run 1 exposed the stream-timeout defect above (fixed, PR #62).
- Run 2 (54 min, end to end): correct shelf read → identified the one
  zero-candidate deficiency (H3) → found an exact-match literature candidate
  (Smooth Local Projections, *ReStat* 2019) → **rejected it via its own
  pre-registered power check** (best 28.7% vs the 80% gate, redesign swept)
  → zero branches/commits/PRs, one production calibration lead escalated to
  humans. Honest rejection is the designed behavior, not a failure mode.
