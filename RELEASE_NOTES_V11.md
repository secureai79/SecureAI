
## Consolidated v11 customer-report and analyzer foundation

- Customer PDF reports now use plain language and separate confirmed/likely risks from low-confidence review leads.
- PDF reports prioritize runtime-code review leads and summarize test/documentation/specification noise instead of dumping every match.
- Customer reports use friendly action names, shorter evidence excerpts, clear explanations of what was found, what could not be confirmed, and what the customer can do next.
- Added/retained the language-analyzer boundary, common IR objects, confidence helper, and centralized capability policy registry.
- The scan pipeline now routes supported file extensions through the language-analyzer registry while preserving the existing Python FileAnalysis/risk behavior.
- JavaScript/TypeScript remains deliberately unscored until a real AST/data-flow analyzer is installed; the architecture is ready for that implementation.

# AI Safety Checkup v11 — Report & Analyzer Foundation

## Included

- Customer-facing PDF Safety Report generated from each completed scan.
- Dashboard button: **Download Safety Report (PDF)**.
- PDF includes Safety Score, risk level, capabilities, AI-control confidence, top risks, evidence, data-flow/capability chains, recommendations, and regression/baseline information.
- PDF is generated from the selected scan and does not embed the full repository.
- Language analyzer boundary introduced.
- Common intermediate representation (IR) added for language-neutral code nodes, edges, and capabilities.
- Central capability policy registry added.
- Confidence labels (`CONFIRMED`, `LIKELY`, `POSSIBLE`) added as shared analysis vocabulary.
- Existing Python analysis remains the source of truth; its behavior is preserved.
- JavaScript/TypeScript remain deliberately unscored until deep AST/data-flow analysis is implemented, preventing regex noise from damaging the Safety Score.
- Existing security hardening from the previous release is retained.

## Verification

- Backend test suite: **56 passed, 0 failed**.
- PDF endpoint verified as an authenticated download for completed scans.

## Next implementation step

Implement the deep JavaScript/TypeScript AST + data-flow analyzer against the common IR, then add Python/JS parity tests for equivalent AI → consequential-action flows.


## Security Analysis Extension

This build adds a conservative application-security layer alongside AI capability analysis.

### New checks
- Exposed API keys and tokens (OpenAI, Stripe, GitHub, Slack, Google, AWS)
- Hardcoded credential assignments
- Sensitive data flowing toward outbound network requests
- Potentially unprotected sensitive HTTP endpoints
- User/AI-controlled data reaching shell execution
- Obvious dynamically constructed SQL queries

Security findings are deterministic and are not passed through the optional LLM refinement step. Secrets are never intentionally copied into report prose beyond the minimum source evidence already available to the finding; customers should rotate any credential that appears to be real.

### Product behavior
The Safety Score can now reflect confirmed application-security findings as well as AI-connected risks. Low-confidence/non-runtime capability matches remain outside the score.

### Important limitation
These checks are static heuristics. They can identify evidence of a potential weakness but cannot prove that an application has been compromised or that an attacker actually exploited it. Runtime attack tracing requires logs/telemetry and is a future capability.

### Developer testing
Security regression tests cover secrets, sensitive-data-to-network flows, unguarded endpoints, command injection, SQL injection, and placeholder-secret suppression.

## v11.1 — Deep JavaScript / TypeScript analysis

- Replaced the JS/TS placeholder analyzer with a TypeScript compiler-API AST bridge.
- Added syntax-aware AI source detection, dangerous-call detection, local taint propagation, and local function-parameter propagation.
- JS/TS findings now use the same `RawFinding` contract and existing risk/scoring pipeline as Python when AST analysis succeeds.
- If the Node/TypeScript runtime is unavailable, JS/TS analysis fails closed and retains the existing unscored fallback behavior.
- Added parity/regression tests covering AI-controlled refunds, unrelated dangerous calls, interprocedural parameter propagation, and TypeScript syntax.

## v11 Customer Data Protection Hardening

This consolidated build adds a privacy/security boundary around the scanner:

- Full repository source remains temporary and is deleted after scans.
- Source snippets are disabled by default; optional snippets are encrypted before persistence.
- Stored evidence is redacted/minimized and raw scan errors are sanitized.
- External LLM refinement is opt-in and requires explicit privacy acknowledgement.
- Scan retention cleanup and authenticated deletion endpoints are included.
- Production GitHub access is GitHub App based with repository-scoped permissions; legacy OAuth is disabled in production.
- OAuth state is durable, expiring and one-time-use rather than process-memory only.
- Production scans execute in a clean subprocess with resource limits and a restricted environment.
- Repository hooks/submodules are disabled during cloning; large blobs are filtered; symlinked files are not followed.
- Authentication has stronger password requirements, short-lived JWTs and token revocation on logout.
- Rate limits protect authentication, repository creation and scan creation at the application layer.
- Production startup rejects unsafe defaults such as wildcard CORS, SQLite, weak JWT secrets and local repository access.
- Security analyzer SQL detection was tightened to require a recognized database sink, avoiding generic frontend `.query()` false positives.
