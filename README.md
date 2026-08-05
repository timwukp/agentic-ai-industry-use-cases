# Agentic AI Industry Use Cases — on AWS Bedrock AgentCore Harness

[繁體中文](README.zh-TW.md)

Industry agentic-AI applications rebuilt on **AWS Bedrock AgentCore Harness** — declarative,
fully-managed agents (no containers, no agent loop to write) with **Gateway MCP tools**,
a **Bedrock Knowledge Base (S3 Vectors)**, **managed Memory**, and a single **Cognito-secured
responsive PWA** frontend.

**All six industries are deployed end-to-end and verified** — each has its own harness,
Gateway with 5 MCP tool targets, Knowledge Base on S3 Vectors, managed Memory, and log/trace
delivery, all reachable from the one PWA. All six also have a purpose-built dashboard backed
by its own REST routes (3-5 per industry), verified against the deployed API and screenshotted
at desktop and mobile widths.

## Architecture

![Architecture](docs/architecture.svg)

### Request flow

![Request flow](docs/request-flow.svg)

**Security posture:** Cognito user pool (TOTP MFA, advanced security, 12-char passwords),
JWT verified at every entry point (harness `customJWTAuthorizer` + API Gateway authorizer),
WAF attached to CloudFront, least-privilege per-Lambda IAM, KMS on data stores, private
S3 behind CloudFront OAC, no long-lived secrets in code.

## Repository layout

| Path | What it is |
|---|---|
| `harnesses/<industry>/` | Declarative harness config template, memory strategies, system prompt |
| `tools/<industry>/` | Gateway Lambda tool handlers + MCP tool schemas |
| `tools/shared/toolkit/` | Shared dispatch, DynamoDB helpers, deterministic market simulator |
| `kb/<industry>/seed-docs/` | Knowledge-base seed documents (policies, product guides) |
| `skills/` | AgentCore Skills (git-sourced; wired post-merge) |
| `infra/cdk/` | 11 CDK stacks: SharedSecurity, Auth, FinanceData, FinanceTools, Api, Web + one `IndustryStack` per non-finance industry (Healthcare, Insurance, Retail, Manufacturing, Realestate) |
| `deploy/` | Orchestrator + idempotent scripts (gateway, memory, seed, render, smoke) |
| `web/` | Unified responsive PWA (Vite + React 19 + Tailwind + Amplify Auth) |
| `tests/` | Unit (pytest + moto), infra (CDK assertions), E2E (Playwright) |

## Deploy

Prereqs: Python 3.11+, Node 22+, AWS credentials, `boto3 >= 1.43.51`.

```bash
make setup            # venv + deps + CDK CLI
make test             # unit + infra tests
make deploy-finance   # CDK → seed → gateway → harness → memory → observability → smoke
make deploy-web       # build PWA → deploy WebStack → publish to CloudFront

# any other industry, same pipeline:
python deploy/deploy.py --industry healthcare|insurance|retail|manufacturing|realestate
```

`deploy/deploy.py` sequences everything and is idempotent — rerun it safely, or resume with
`--from-step gateway` / `--only smoke`. Each industry's CDK outputs are merged into
`deploy/outputs/cdk-outputs.json` rather than overwriting it, so deploying industry N keeps
industries 1..N-1 usable. The AgentCore Harness Builder skill's scripts (preflight, validate,
create/update harness, invoke) are used underneath; set `HARNESS_SKILL_DIR` if the skill
lives elsewhere.

### Verify

```bash
make test                                   # unit (pytest + moto) + infra + web (node --test)
.venv/bin/python deploy/smoke_suite.py      # gateway tools, KB, memory (JWT end-user path)
make verify-harnesses                       # every LIVE harness can actually reach its tools
cd tests/e2e && BASE_URL=https://<cloudfront> E2E_EMAIL=... E2E_PASSWORD=... npx playwright test
```

`make verify-harnesses` exists because of a failure nothing else caught. The live harnesses had
drifted to an `allowedTools` pattern list that matched nothing, so each agent could see only its
`skills` tool — and instead of refusing, it answered from memory and invented market data
(reporting the S&P 500 at 5,248 when the tool returns 6,120.35). The gateway was `READY`, all
targets `READY`, all 17 tools worked when called directly over MCP, IAM simulated as `allowed`,
and every deploy step exited 0. The only trace was `"Unknown tool: …"` inside a tool-result event
that both the smoke script and the web client discarded. So the check asks a live harness to
*use* a tool and reads the **tool-result events, not the prose** — an agent cut off from its
tools produces confident-looking text, which is why asserting on wording would be worse than no
check at all.

## The six industries

Every industry runs the same shape: 4 domain tool Lambdas + a KB-search Lambda behind its own
Gateway (5 MCP targets), one harness, one Knowledge Base, one Memory.

| Industry | Agent | Gateway tool targets | UI |
|---|---|---|---|
| Finance Trading | `finance_trading_assistant` | market-data / portfolio / risk / trading / kb | Dashboard + chat |
| Healthcare Medical | `healthcare_medical_assistant` | clinical / analytics / records / scheduling / kb | Patient 360 dashboard + chat |
| Insurance Claims | `insurance_claims_assistant` | claims / fraud-detection / policy / settlement / kb | Claims queue dashboard + chat |
| Retail Inventory | `retail_inventory_assistant` | inventory / demand-forecast / supplier / pricing / kb | Inventory dashboard + chat |
| Manufacturing Maintenance | `manufacturing_maintenance_assistant` | equipment / prediction / maintenance / parts / kb | Asset health dashboard + chat |
| Real Estate Valuation | `real_estate_valuation_assistant` | valuation / market / investment / property / kb | Valuation dashboard + chat |

All six were brought online by the same command — `python deploy/deploy.py --industry <name>` —
with **zero new stack code** per industry: the parameterized `IndustryStack` plus the
gateway/harness/memory/observability scripts read everything from `deploy/industries.py`.
Each dashboard's REST routes are declared in `DASHBOARD_ROUTES` (`infra/cdk/app.py`) and served
by one `dashboard_api` Lambda per industry that imports the *same* tool handlers the agent calls
through the Gateway — so a number on a tile and the number the agent quotes in chat come from one
function, not two implementations.

### Dashboard coherence

The simulated payloads are built so that figures describing one entity cannot contradict each
other. Every derived number is computed from the number displayed above it, and every route
touching the same entity reads from one shared basis (`property_basis`, `asset_basis`,
`retail_basis`, `market_basis` in `tools/shared/toolkit/`). Independent draws produce visible
nonsense — a market tile reading `$528K` above its own history chart topping out at `$780K`, a
tile labelled `Median $/Sq Ft` showing a rate no row in the table beneath it contains, or a
`YoY +8.8%` tile above a chart headed `+8.1% over period` for the same twelve months.
`tests/unit/test_industry_dashboard_apis.py` pins each of these as a regression.

### Starter questions

Each industry's empty AI Assistant pane offers 3–5 starter questions
(`web/src/industries/starterPrompts.ts`) so a first-time visitor has somewhere to click. They
are worded as a practitioner in that seat would ask, read-only first so the opening click never
mutates state, and clicking one sends it immediately (unlike the dashboard's **Ask agent**
buttons, which prefill because they fire mid-conversation).

Every entity id and enum value in a prompt is grounded in the real tool data. This matters more
than it sounds: the shared bases fabricate rather than fail, so `sku_basis("SKU-1001")` returns a
plausible "Product 1001" and the agent confidently answers about an item that exists nowhere else
in the app. `tests/unit/test_starter_prompts.py` parses the TypeScript (rather than duplicating
the list, which would drift) and asserts every SKU, asset, provider, patient, market and ticker
against the shared catalogs, every stated enum against the handler's own accepted set, and calls
all 26 tool paths to confirm each returns populated data.

## Data honesty

Market data is a **deterministic simulation** (`tools/shared/toolkit/market_sim.py`) — stable
within a trading day, reproducible, no API keys. Every simulated payload carries
`"source": "simulated"` and the agent is instructed to disclose it. Orders are real writes to
the demo order book (DynamoDB) and genuinely mutate positions. Real-world lookups (news, SEC
filings) go through the harness's built-in browser tool.

## Costs

Rough demo-scale monthly costs (us-east-1): CloudFront/S3/Lambda/DynamoDB on-demand ≈ $1–5,
S3 Vectors ≈ pennies, Cognito Plus per-MAU ≈ $0 at demo scale, no NAT/OpenSearch. The main
variable is Bedrock model usage during testing.

## Disclaimer

Demo/reference architecture. Simulated financial data — not investment advice. Review
security, compliance, and cost for your own environment before production use.

## License

Apache-2.0
