# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities **privately** via GitHub:
**Security tab → Report a vulnerability** (GitHub private vulnerability
reporting), or if that is unavailable, open a GitHub issue that says only
"security issue — please contact me" without technical details.

- You can expect an acknowledgment within **72 hours** and a status update at
  least every **7 days** until resolution.
- Accepted reports are fixed on `main` and redeployed; you will be credited
  in the advisory unless you prefer otherwise.
- This is a demonstration project — there is **no bug bounty**.

Please do not run automated scanners or load tests against the deployed demo
(it is WAF-fronted and rate-limited; findings from DoS-style testing are out
of scope).

## Supported Versions

This repository is a continuously deployed reference implementation, not a
versioned product. Only the tip of `main` (which is what the live demo runs)
receives security fixes.

| Version | Supported |
| --- | --- |
| `main` (deployed demo) | ✅ |
| anything else | ❌ |

## Security Architecture (what this demo actually does)

Verified design properties of the deployed system — see
[docs/architecture.svg](docs/architecture.svg) and the
[README](README.md#architecture) for the full picture:

- **Authentication end to end**: Amazon Cognito user pool (12-char minimum
  passwords, optional TOTP MFA, advanced security mode). The user's JWT is
  verified at **every** entry point — CloudFront `/agent/*` requests by the
  AgentCore runtime's `customJWTAuthorizer`, and dashboard REST calls by the
  API Gateway JWT authorizer. There are no unauthenticated data endpoints.
- **Edge protection**: CloudFront with AWS WAF attached; the static site is a
  private S3 bucket behind Origin Access Control.
- **Least-privilege IAM**: each Lambda, harness, and scheduled job has its own
  execution role scoped to the specific resources it touches (per-industry
  Gateway tool Lambdas, the quant batch, the theory-scout chain).
- **No long-lived credentials in code**: third-party market-data API keys live
  in SSM SecureString; test-account credentials live in AWS Secrets Manager;
  the research scout's GitHub token is a fine-grained PAT scoped to this
  single repository (contents + pull requests only) with an expiry date.
- **Agent write-actions are gated**: every state-changing tool call
  (orders, claims, purchase orders, work orders, appointments) sits behind
  explicit user confirmation and, in the business logic, monetary/authority
  approval thresholds — see [docs/business-flows.md](docs/business-flows.md).
- **Autonomous agents cannot merge**: the theory scout can only open branches
  and pull requests; merging is human-only, and repository pushes go through
  reviewed PRs.

## Scope

**In scope**: code in this repository (web app, CDK stacks, Lambda tools,
harness configurations, deploy scripts) and the deployed demo's
authentication/authorization behavior.

**Out of scope**: vulnerabilities in AWS managed services themselves (report
to AWS), the third-party market-data providers, denial-of-service findings,
and the **simulated** business data (it is synthetic by design — the demo
discloses `source: simulated` on such data and holds no real customer, health,
claims, or trading records; the only personal data processed is the Cognito
account email).

## Disclaimer

This project demonstrates architecture patterns for agentic AI systems. The
compliance gates shown in the demo flows (HIPAA, fair-claims, Fair Housing,
suitability, LOTO) are **illustrations of how to encode such controls**, not
certified implementations — do not use them as-is in regulated production
systems without your own compliance review.
